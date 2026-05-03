import os
import argparse
from pickle import UnpicklingError
from platform import python_branch
import pandas as pd
import csv
from utils import upload_to_gcs
import sys
import io
import zipfile
import traceback
import tempfile
import shutil
import torch
from google.cloud import storage
import subprocess

from fickling.pytorch import PyTorchModelWrapper
from fickling.fickle import Pickled, Interpreter
from fickling.tracing import Trace
from pytorch_injector import (
    pytorch_injector,
    obfuscated_pytorch_injector,
    inject_at_end,
)
from payload_generator import get_random_pkl_file
from opensource_runner import do_open_source_checks


SUPPORTED_EXTENSIONS = (".pkl", ".pickle", ".pt", ".pth", ".bin")


def delete_file_gcs(bucket_name, file_path):
    """
    Delete a single file from a GCS bucket
    """
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(file_path)
    blob.delete()


def process_gcs_files_with_tracing(
    bucket_name,
    prefix=None,
    local_work_dir=None,
):
    if local_work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="gcs_trace_processing_")
        cleanup_work_dir = True
    else:
        work_dir = local_work_dir
        os.makedirs(work_dir, exist_ok=True)
        cleanup_work_dir = False

    print(f"Using work directory: {work_dir}")

    log_file_path = os.path.join(work_dir, "gcs-injection.txt")

    already_downloaded = set()
    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as log_file:
            already_downloaded = {line.strip() for line in log_file if line.strip()}

    try:
        print(f"Listing files in bucket '{bucket_name}' with prefix '{prefix}'...")
        gcs_files = list_files_gcs(bucket_name, prefix)
        if not gcs_files:
            print("No files found in the specified bucket/prefix.")
            return
        print(f"Found {len(gcs_files)} files in GCS")

        for blob_name in gcs_files:
            if blob_name in already_downloaded:
                print(f"Already processed {blob_name}, skipping.")
                continue

            if blob_name.lower().endswith(".trace.txt"):
                print(f"Skipping trace file: {blob_name}")
                continue

            if not any(
                blob_name.lower().endswith(ext)
                for ext in SUPPORTED_EXTENSIONS + (".zip",)
            ):
                print(f"Skipping unsupported file: {blob_name}")
                continue

            if os.path.basename(blob_name) == "pytorch_model_injected.bin":
                local_filename = os.path.basename(blob_name)
                after_injected = blob_name.split(f"{prefix}")[1]
                model_dir = after_injected.split("/")[0]
                local_file_path = os.path.join(work_dir, model_dir, local_filename)
                local_dir_path = os.path.join(work_dir, model_dir)
                os.makedirs(local_dir_path, exist_ok=True)

                if download_from_gcs(bucket_name, blob_name, local_file_path):
                    if blob_name.lower().endswith(".zip"):
                        process_zip_file(local_file_path, work_dir)
                    else:
                        process_single_file(local_file_path)

                    with open(log_file_path, "a") as log_file:
                        log_file.write(f"{blob_name}\n")

                    os.remove(local_file_path)
                    print(f"Cleaned up: {local_file_path}")
                else:
                    print(f"Failed to download: {blob_name}")
    finally:
        if cleanup_work_dir and os.path.exists(work_dir):
            shutil.rmtree(work_dir)
            print(f"Cleaned up work directory: {work_dir}")


def download_and_inject_pytorch(
    bucket_name,
    prefix=None,
    local_work_dir=None,
):
    """
    Args:
        bucket_name (str): Name of the GCS bucket
        prefix (str, optional): Prefix to filter files in the bucket
        local_work_dir (str, optional): Local directory for processing. If None, uses temp dir.
    """
    if local_work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="gcs_trace_processing_")
        cleanup_work_dir = True
    else:
        work_dir = local_work_dir
        os.makedirs(work_dir, exist_ok=True)
        cleanup_work_dir = False

    print(f"Using work directory: {work_dir}")

    try:
        print(f"Listing files in bucket '{bucket_name}' with prefix '{prefix}'...")
        gcs_files = list_files_gcs(bucket_name, prefix)
        pypi_files = list_files_gcs(bucket_name, prefix)

        if not gcs_files:
            print("No files found in the specified bucket/prefix.")
            return

        print(f"Found {len(gcs_files)} files in GCS")

        for blob_name in gcs_files:
            if os.path.basename(blob_name) == "pytorch_model.bin":
                injected_blob = blob_name.replace(
                    "pytorch_model.bin", "pytorch_model_injected_pypi.bin"
                )

                if injected_blob in gcs_files or injected_blob in pypi_files:
                    print(
                        f"Skipping {blob_name} because injected pypi version already exists."
                    )
                    continue

                # if not any(
                #     blob_name.lower().endswith(ext)
                #     for ext in SUPPORTED_EXTENSIONS + (".zip",)
                # ):
                #     continue
                #
                local_filename = os.path.basename(blob_name)
                after_injected = blob_name.split(f"{prefix}")[1]
                model_dir = after_injected.split("/")[0]
                local_file_path = os.path.join(work_dir, model_dir, local_filename)
                local_dir_path = os.path.join(work_dir, model_dir)
                os.makedirs(local_dir_path, exist_ok=True)

                if download_from_gcs(bucket_name, blob_name, local_file_path):
                    output_path = os.path.join(
                        os.path.dirname(local_file_path),
                        "pytorch_model_injected_pypi.bin",
                    )
                    injection_success = pytorch_injector(
                        local_file_path,
                        output_path,
                        None,
                        "pypi_injection_image_classification.csv",
                    )
                    if injection_success:
                        do_open_source_checks(
                            output_path,
                            "opensource_pypi_image_classification.csv",
                            "./.venv/bin/activate",
                        )
                        base_blob_path = f"{prefix}{model_dir.replace('/', '__')}"
                        injected_blob_name = (
                            f"{base_blob_path}/pytorch_model_injected_pypi.bin"
                        )
                        upload_to_gcs(output_path, bucket_name, injected_blob_name)
                        try:
                            os.remove(output_path)
                        except FileNotFoundError:
                            pass
                    else:
                        print("injection failed")
                    os.remove(local_file_path)
                    print(f"Cleaned up: {local_file_path}")
                    try:
                        os.remove(output_path)
                    except FileNotFoundError:
                        pass
                else:
                    print(f"Failed to download: {blob_name}")

    finally:
        if cleanup_work_dir and os.path.exists(work_dir):
            shutil.rmtree(work_dir)
            print(f"Cleaned up work directory: {work_dir}")


def download_and_inject_obfuscated(
    bucket_name,
    payload_dir,
    prefix=None,
    local_work_dir=None,
):
    """
    Args:
        bucket_name (str): Name of the GCS bucket
        payload_dir : Path to directory containing obfuscated payloads
        prefix (str, optional): Prefix to filter files in the bucket
        local_work_dir (str, optional): Local directory for processing. If None, uses temp dir.
    """
    if local_work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="gcs_trace_processing_")
        cleanup_work_dir = True
    else:
        work_dir = local_work_dir
        os.makedirs(work_dir, exist_ok=True)
        cleanup_work_dir = False

    print(f"Using work directory: {work_dir}")
    to_filter = set()

    with open(
        "../Results/filter_names_injected.csv", newline="", encoding="utf-8"
    ) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            to_filter.add(row["name"].replace("/", "__"))

    print(to_filter)

    try:
        print(f"Listing files in bucket '{bucket_name}' with prefix '{prefix}'...")
        gcs_files = list_files_gcs(bucket_name, prefix)
        pypi_files = list_files_gcs(bucket_name, prefix)

        if not gcs_files:
            print("No files found in the specified bucket/prefix.")
            return

        print(f"Found {len(gcs_files)} files in GCS")
        for blob_name in gcs_files:
            for checker in to_filter:
                if checker in blob_name and blob_name.endswith("pytorch_model.bin"):
                    base_blob_path = os.path.dirname(blob_name)

                    injected_prefix = f"{base_blob_path}/pytorch_model_injected_"
                    injected_suffix = "_obfuscated.bin"

                    def injected_exists(files):
                        return any(
                            f.startswith(injected_prefix)
                            and f.endswith(injected_suffix)
                            for f in files
                        )

                    if injected_exists(gcs_files) or injected_exists(pypi_files):
                        print(
                            f"Skipping {blob_name} because injected obfuscated version already exists."
                        )
                        continue
                    # if not any(
                    #     blob_name.lower().endswith(ext)
                    #     for ext in SUPPORTED_EXTENSIONS + (".zip",)
                    # ):
                    #     continue
                    #
                    local_filename = os.path.basename(blob_name)
                    after_injected = blob_name.split(f"{prefix}")[1]
                    model_dir = after_injected.split("/")[0]
                    local_file_path = os.path.join(work_dir, model_dir, local_filename)
                    local_dir_path = os.path.join(work_dir, model_dir)
                    os.makedirs(local_dir_path, exist_ok=True)

                    if download_from_gcs(bucket_name, blob_name, local_file_path):
                        payload_file = get_random_pkl_file(payload_dir)
                        payload_name = "".join(
                            "".join(str(payload_file).split("/")[-1:]).split(".")[0]
                        )
                        output_path = os.path.join(
                            os.path.dirname(local_file_path),
                            f"pytorch_model_injected_{payload_name}_obfuscated.bin",
                        )
                        injection_success = obfuscated_pytorch_injector(
                            local_file_path,
                            output_path,
                            "payloads/obfuscated",
                            "injection_log_pytorch_obfuscated.csv",
                            chosen_file=payload_file,
                        )
                        if injection_success:
                            base_blob_path = f"{prefix}{model_dir.replace('/', '__')}"
                            injected_blob_name = f"{base_blob_path}/pytorch_model_injected_{payload_name}_obfuscated.bin"
                            upload_to_gcs(output_path, bucket_name, injected_blob_name)
                            try:
                                os.remove(output_path)
                            except FileNotFoundError:
                                pass
                        else:
                            print("injection failed")
                        os.remove(local_file_path)
                        print(f"Cleaned up: {local_file_path}")
                        try:
                            os.remove(output_path)
                        except FileNotFoundError:
                            pass
                    else:
                        print(f"Failed to download: {blob_name}")

    finally:
        if cleanup_work_dir and os.path.exists(work_dir):
            shutil.rmtree(work_dir)
            print(f"Cleaned up work directory: {work_dir}")


def download_and_inject_weights(
    bucket_name,
    payload_dir,
    pyenv=None,
    prefix=None,
    local_work_dir=None,
):
    """
    Args:
        bucket_name (str): Name of the GCS bucket
        payload_dir : Path to directory containing obfuscated payloads
        prefix (str, optional): Prefix to filter files in the bucket
        local_work_dir (str, optional): Local directory for processing. If None, uses temp dir.
    """
    if local_work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="gcs_trace_processing_")
        cleanup_work_dir = True
    else:
        work_dir = local_work_dir
        os.makedirs(work_dir, exist_ok=True)
        cleanup_work_dir = False

    print(f"Using work directory: {work_dir}")
    to_filter = set()

    with open(
        "../Results/filter_names_injected.csv", newline="", encoding="utf-8"
    ) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            to_filter.add(row["name"].replace("/", "__"))

    print(to_filter)

    try:
        print(f"Listing files in bucket '{bucket_name}' with prefix '{prefix}'...")
        gcs_files = list_files_gcs(bucket_name, prefix)
        pypi_files = list_files_gcs(bucket_name, prefix)

        if not gcs_files:
            print("No files found in the specified bucket/prefix.")
            return

        print(f"Found {len(gcs_files)} files in GCS")
        for blob_name in gcs_files:
            for checker in to_filter:
                if checker in blob_name and blob_name.endswith("pytorch_model.bin"):
                    base_blob_path = os.path.dirname(blob_name)

                    injected_prefix = f"{base_blob_path}/pytorch_model_injected_"
                    injected_suffix = "_weights_bypass.bin"

                    def injected_exists(files):
                        return any(
                            f.startswith(injected_prefix)
                            and f.endswith(injected_suffix)
                            for f in files
                        )

                    if injected_exists(gcs_files) or injected_exists(pypi_files):
                        print(
                            f"Skipping {blob_name} because injected obfuscated version already exists."
                        )
                        continue
                    # if not any(
                    #     blob_name.lower().endswith(ext)
                    #     for ext in SUPPORTED_EXTENSIONS + (".zip",)
                    # ):
                    #     continue
                    #
                    local_filename = os.path.basename(blob_name)
                    after_injected = blob_name.split(f"{prefix}")[1]
                    model_dir = after_injected.split("/")[0]
                    local_file_path = os.path.join(work_dir, model_dir, local_filename)
                    local_dir_path = os.path.join(work_dir, model_dir)
                    os.makedirs(local_dir_path, exist_ok=True)

                    if download_from_gcs(bucket_name, blob_name, local_file_path):
                        payload_file = get_random_pkl_file(payload_dir)
                        payload_name = "".join(
                            "".join(str(payload_file).split("/")[-1:]).split(".")[0]
                        )
                        output_path = os.path.join(
                            os.path.dirname(local_file_path),
                            f"pytorch_model_injected_{payload_name}_weights_bypass.bin",
                        )
                        injection_success = inject_at_end(
                            local_file_path,
                            output_path,
                            payload_file,
                            "injection_log_pytorch_weights_bypass.csv",
                        )
                        if injection_success:
                            do_open_source_checks(
                                output_path,
                                "weights_bypass_opensource_results.csv",
                            )
                            base_blob_path = f"{prefix}{model_dir.replace('/', '__')}"
                            injected_blob_name = f"{base_blob_path}/pytorch_model_injected_{payload_name}_weights_bypass.bin"
                            upload_to_gcs(output_path, bucket_name, injected_blob_name)
                            try:
                                os.remove(output_path)
                            except FileNotFoundError:
                                pass
                        else:
                            print("injection failed")
                        os.remove(local_file_path)
                        print(f"Cleaned up: {local_file_path}")
                        try:
                            os.remove(output_path)
                        except FileNotFoundError:
                            pass
                    else:
                        print(f"Failed to download: {blob_name}")

    finally:
        if cleanup_work_dir and os.path.exists(work_dir):
            shutil.rmtree(work_dir)
            print(f"Cleaned up work directory: {work_dir}")


def download_and_inject_external(
    bucket_name,
    payload_dir,
    pyenv=None,
    prefix=None,
    local_work_dir=None,
):
    """
    Args:
        bucket_name (str): Name of the GCS bucket
        payload_dir : Path to directory containing obfuscated payloads
        prefix (str, optional): Prefix to filter files in the bucket
        local_work_dir (str, optional): Local directory for processing. If None, uses temp dir.
    """
    if local_work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="gcs_trace_processing_")
        cleanup_work_dir = True
    else:
        work_dir = local_work_dir
        os.makedirs(work_dir, exist_ok=True)
        cleanup_work_dir = False

    print(f"Using work directory: {work_dir}")
    to_filter = set()

    with open(
        "../Results/filter_names_injected.csv", newline="", encoding="utf-8"
    ) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            to_filter.add(row["name"].replace("/", "__"))

    print(to_filter)

    try:
        print(f"Listing files in bucket '{bucket_name}' with prefix '{prefix}'...")
        gcs_files = list_files_gcs(bucket_name, prefix)
        pypi_files = list_files_gcs(bucket_name, prefix)

        if not gcs_files:
            print("No files found in the specified bucket/prefix.")
            return

        print(f"Found {len(gcs_files)} files in GCS")

        for blob_name in gcs_files:
            for checker in to_filter:
                if checker in blob_name and blob_name.endswith("pytorch_model.bin"):
                    base_blob_path = os.path.dirname(blob_name)

                    injected_prefix = f"{base_blob_path}/pytorch_model_injected_"
                    injected_suffix = "_external.bin"

                    def injected_exists(files):
                        return any(
                            f.startswith(injected_prefix)
                            and f.endswith(injected_suffix)
                            for f in files
                        )

                    if injected_exists(gcs_files) or injected_exists(pypi_files):
                        print(
                            f"Skipping {blob_name} because injected obfuscated version already exists."
                        )
                        continue
                    # if not any(
                    #     blob_name.lower().endswith(ext)
                    #     for ext in SUPPORTED_EXTENSIONS + (".zip",)
                    # ):
                    #     continue
                    #
                    local_filename = os.path.basename(blob_name)
                    after_injected = blob_name.split(f"{prefix}")[1]
                    model_dir = after_injected.split("/")[0]
                    local_file_path = os.path.join(work_dir, model_dir, local_filename)
                    local_dir_path = os.path.join(work_dir, model_dir)
                    os.makedirs(local_dir_path, exist_ok=True)

                    if download_from_gcs(bucket_name, blob_name, local_file_path):
                        payload_file = get_random_pkl_file(payload_dir)
                        payload_name = "".join(
                            "".join(str(payload_file).split("/")[-1:]).split(".")[0]
                        )
                        output_path = os.path.join(
                            os.path.dirname(local_file_path),
                            f"pytorch_model_injected_{payload_name}_external.bin",
                        )
                        injection_success = pytorch_injector(
                            local_file_path,
                            output_path,
                            payload_file,
                            "injection_log_pytorch_external.csv",
                        )
                        if injection_success:
                            do_open_source_checks(
                                output_path,
                                "external_opensource_results.csv",
                            )
                            base_blob_path = f"{prefix}{model_dir.replace('/', '__')}"
                            injected_blob_name = f"{base_blob_path}/pytorch_model_injected_{payload_name}_external.bin"
                            upload_to_gcs(output_path, bucket_name, injected_blob_name)
                            try:
                                os.remove(output_path)
                            except FileNotFoundError:
                                pass
                        else:
                            print("injection failed")
                        os.remove(local_file_path)
                        print(f"Cleaned up: {local_file_path}")
                        try:
                            os.remove(output_path)
                        except FileNotFoundError:
                            pass
                    else:
                        print(f"Failed to download: {blob_name}")

    finally:
        if cleanup_work_dir and os.path.exists(work_dir):
            shutil.rmtree(work_dir)
            print(f"Cleaned up work directory: {work_dir}")


def process_zip_file(zip_file_path, work_dir):
    """
    Extract zip file, process contents, and clean up.
    """
    extract_dir = os.path.join(work_dir, f"extracted_{os.path.basename(zip_file_path)}")

    if extract_and_cleanup(zip_file_path, extract_dir):
        for path, folders, files in os.walk(extract_dir):
            trace_files = [f for f in files if f.lower().endswith(".trace.txt")]
            if trace_files:
                print(f"Skipping {path}, found a .trace.txt in it")
                continue

            for filename in files:
                lower_filename = filename.lower()
                if lower_filename.endswith(SUPPORTED_EXTENSIONS):
                    file_path = os.path.join(path, filename)
                    process_single_file(file_path)

        # Clean up extracted directory
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
            print(f"Cleaned up extracted directory: {extract_dir}")


def process_single_file(file_path):
    """
    Process a single file to generate trace output.
    """
    print(f"Processing: {file_path}")
    try:
        if is_zip_model(file_path):
            fickled_model = PyTorchModelWrapper(file_path, force=True)
            pickles = fickled_model.pickled
        else:
            with open(file_path, "rb") as f:
                pickles = Pickled.load(f)

        interpreter = Interpreter(pickles)
        trace = Trace(interpreter)

        buffer = io.StringIO()
        sys_stdout = sys.stdout
        sys.stdout = buffer
        try:
            trace.run()
        finally:
            sys.stdout = sys_stdout

        trace_output = buffer.getvalue()

        trace_file = file_path + ".trace.txt"
        with open(trace_file, "w") as f:
            f.write(trace_output)
        print(f"Saved trace to: {trace_file}")

    except Exception as e:
        print(f"Failed to process '{file_path}': {type(e).__name__}: {e}")
        traceback.print_exc()
        print()


def extract_and_cleanup(bin_file_path, extract_dir):
    """
    Extract zip file and clean up non-pickle files.
    """
    try:
        with zipfile.ZipFile(bin_file_path, "r") as zip_ref:
            zip_ref.extractall(extract_dir)
            print(f"Extracted contents to: {extract_dir}")

        pkl_files = []
        for root, _, files in os.walk(extract_dir):
            for file in files:
                if file.endswith((".pkl", ".pickle", ".pt")):
                    pkl_files.append(os.path.join(root, file))

        if not pkl_files:
            print("No .pkl or .pickle files found after extraction.")
            return False

        print(f"Found {len(pkl_files)} pickle files. Cleaning up...")

        for root, dirs, files in os.walk(extract_dir, topdown=False):
            for file in files:
                fpath = os.path.join(root, file)
                if not file.endswith((".pkl", ".pickle", ".pt")):
                    os.remove(fpath)
            for d in dirs:
                dirpath = os.path.join(root, d)
                if not os.listdir(dirpath):
                    os.rmdir(dirpath)

        return True

    except zipfile.BadZipFile:
        print("Not a zip archive.")
        return False
    except Exception as e:
        print(f"Extraction error: {e}")
        return False


def list_files_gcs(bucket_name, prefix=None):
    storage_client = storage.Client()
    blobs = storage_client.list_blobs(bucket_name, prefix=prefix)
    res = [blob.name for blob in blobs]
    return res


def download_from_gcs(bucket_name, blob_name, destination_file_name):
    try:
        client = storage.Client()
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        print(
            f"Downloading {blob_name} from GCP bucket {bucket_name} to {destination_file_name}"
        )
        blob.download_to_filename(destination_file_name)
        print(f"Successfully downloaded to {destination_file_name}")
        return True
    except Exception as e:
        print(f"Error downloading from GCS: {e}")
        return False


def download_and_run_opensource(
    bucket_name, prefix=None, local_work_dir=None, python_env=None
):
    """
    Args:
        bucket_name (str): Name of the GCS bucket
        prefix (str, optional): Prefix to filter files in the bucket
        local_work_dir (str, optional): Local directory for processing. If None, uses temp dir.
    """
    # Create or use provided work directory
    sys.path.append("payloads/obfuscated")
    if local_work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="gcs_trace_processing_")
        cleanup_work_dir = True
    else:
        work_dir = local_work_dir
        os.makedirs(work_dir, exist_ok=True)
        cleanup_work_dir = False

    print(f"Using work directory: {work_dir}")
    csv_file = "opensource_tools_results.csv"
    file_exists = os.path.isfile(csv_file)

    # if file_exists:
    #     already_downloaded = pd.read_csv(csv_file)["name"].tolist()
    #     already_downloaded = [
    #         f"{p.split(os.sep)[p.split(os.sep).index('downloaded_injected') + 1]}/{p.split(os.sep)[p.split(os.sep).index('downloaded_injected') + 2]}"
    #         for p in already_downloaded
    #         if "downloaded_injected" in p
    #     ]
    # else:
    already_downloaded = []

    print(already_downloaded)
    try:
        print(f"Listing files in bucket '{bucket_name}' with prefix '{prefix}'...")
        gcs_files = list_files_gcs(bucket_name, prefix)

        if not gcs_files:
            print("No files found in the specified bucket/prefix.")
            return

        print(f"Found {len(gcs_files)} files in GCS")

        for blob_name in gcs_files:
            blob_name_split = blob_name.split(":")[0]

            parts = blob_name_split.split(os.sep)
            if "injected_models" in parts:
                idx = parts.index("injected_models")
                model_name = "/".join(parts[idx + 1 :])
                file_name = parts[-1]
                if file_name.endswith("obfuscated.bin"):
                    print("found obfuscated, scanning")
                    print(model_name)
                    if model_name in already_downloaded:
                        print(
                            f"Skipping {blob_name} because {model_name} is already scanned"
                        )
                        continue

                    print(f"Processing {blob_name}")  # if not any(
                    #     blob_name.lower().endswith(ext)
                    #     for ext in SUPPORTED_EXTENSIONS + (".zip",)
                    # ):
                    #     continue
                    #
                    local_filename = os.path.basename(blob_name)
                    after_injected = blob_name.split(f"{prefix}")[1]
                    model_dir = after_injected.split("/")[0]
                    local_file_path = os.path.join(work_dir, model_dir, local_filename)
                    local_dir_path = os.path.join(work_dir, model_dir)
                    os.makedirs(local_dir_path, exist_ok=True)

                    if download_from_gcs(bucket_name, blob_name, local_file_path):
                        try:
                            scanning_result = do_open_source_checks(
                                local_file_path,
                                "obfuscaed_opensource_results.csv",
                                python_env=python_env,
                            )
                            print("scanning completed for", local_file_path)
                        except Exception as e:
                            print("Scannign failed with error:", e)
                        os.remove(local_file_path)
                        print(f"Cleaned up: {local_file_path}")
                    else:
                        print(f"Failed to download: {blob_name}")

    finally:
        if cleanup_work_dir and os.path.exists(work_dir):
            shutil.rmtree(work_dir)
            print(f"Cleaned up work directory: {work_dir}")


def trace_and_opensource_gcs(
    bucket_name, prefix=None, local_work_dir=None, python_env=None
):
    """
    Args:
        bucket_name (str): Name of the GCS bucket
        prefix (str, optional): Prefix to filter files in the bucket
        local_work_dir (str, optional): Local directory for processing. If None, uses temp dir.
    """
    if local_work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="gcs_trace_processing_")
        cleanup_work_dir = True
    else:
        work_dir = local_work_dir
        os.makedirs(work_dir, exist_ok=True)
        cleanup_work_dir = False

    print(f"Using work directory: {work_dir}")

    log_file_path = os.path.join(work_dir, "text-gen-injected-benign.txt")

    already_downloaded = set()
    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as log_file:
            already_downloaded = {line.strip() for line in log_file if line.strip()}

    try:
        print(f"Listing files in bucket '{bucket_name}' with prefix '{prefix}'...")
        gcs_files = list_files_gcs(bucket_name, prefix)
        if not gcs_files:
            print("No files found in the specified bucket/prefix.")
            return
        print(f"Found {len(gcs_files)} files in GCS")

        for blob_name in gcs_files:
            if blob_name in already_downloaded:
                print(f"Already processed {blob_name}, skipping.")
                continue

            if blob_name.lower().endswith(".trace.txt"):
                print(f"Skipping trace file: {blob_name}")
                continue

            if not any(
                blob_name.lower().endswith(ext)
                for ext in SUPPORTED_EXTENSIONS + (".zip",)
            ):
                print(f"Skipping unsupported file: {blob_name}")
                continue

            if os.path.basename(blob_name) == "pytorch_model.bin":
                local_filename = os.path.basename(blob_name)
                after_injected = blob_name.split(f"{prefix}")[1]
                model_dir = after_injected.split("/")[0]
                local_file_path = os.path.join(work_dir, model_dir, local_filename)
                local_dir_path = os.path.join(work_dir, model_dir)
                os.makedirs(local_dir_path, exist_ok=True)

                if download_from_gcs(bucket_name, blob_name, local_file_path):
                    if blob_name.lower().endswith(".zip"):
                        process_zip_file(local_file_path, work_dir)
                    else:
                        process_single_file(local_file_path)

                    with open(log_file_path, "a") as log_file:
                        log_file.write(f"{blob_name}\n")

                    do_open_source_checks(
                        local_file_path,
                        "benign_injected_opensource.csv",
                        python_env=python_env,
                    )
                    # Clean up
                    os.remove(local_file_path)
                    print(f"Cleaned up: {local_file_path}")
                else:
                    print(f"Failed to download: {blob_name}")
    finally:
        if cleanup_work_dir and os.path.exists(work_dir):
            shutil.rmtree(work_dir)
            print(f"Cleaned up work directory: {work_dir}")


def opensource_gcs(
    bucket_name, extension=None, prefix=None, local_work_dir=None, python_env=None
):
    """
    Args:
        bucket_name (str): Name of the GCS bucket
        prefix (str, optional): Prefix to filter files in the bucket
        local_work_dir (str, optional): Local directory for processing. If None, uses temp dir.
    """
    if local_work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="gcs_trace_processing_")
        cleanup_work_dir = True
    else:
        work_dir = local_work_dir
        os.makedirs(work_dir, exist_ok=True)
        cleanup_work_dir = False

    log_file_path = os.path.join(work_dir, f"{extension}_scanning_opensource.txt")

    already_downloaded = set()
    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as log_file:
            already_downloaded = {line.strip() for line in log_file if line.strip()}

    try:
        print(f"Listing files in bucket '{bucket_name}' with prefix '{prefix}'...")
        gcs_files = list_files_gcs(bucket_name, prefix)
        if not gcs_files:
            print("No files found in the specified bucket/prefix.")
            return
        print(f"Found {len(gcs_files)} files in GCS")

        for blob_name in gcs_files:
            if blob_name in already_downloaded:
                print(f"Already processed {blob_name}, skipping.")
                continue

            if blob_name.lower().endswith(".trace.txt"):
                print(f"Skipping trace file: {blob_name}")
                continue

            if not any(
                blob_name.lower().endswith(ext)
                for ext in SUPPORTED_EXTENSIONS + (".zip",)
            ):
                print(f"Skipping unsupported file: {blob_name}")
                continue

            if os.path.basename(blob_name).endswith(f"{extension}.bin"):
                local_filename = os.path.basename(blob_name)
                after_injected = blob_name.split(f"{prefix}")[1]
                model_dir = after_injected.split("/")[0]
                local_file_path = os.path.join(work_dir, model_dir, local_filename)
                local_dir_path = os.path.join(work_dir, model_dir)
                os.makedirs(local_dir_path, exist_ok=True)

                if download_from_gcs(bucket_name, blob_name, local_file_path):
                    # Process the downloaded file
                    # if blob_name.lower().endswith(".zip"):
                    #     process_zip_file(local_file_path, work_dir)
                    # else:
                    #     process_single_file(local_file_path)

                    with open(log_file_path, "a") as log_file:
                        log_file.write(f"{blob_name}\n")

                    do_open_source_checks(
                        local_file_path,
                        f"{extension}_opensource_scanning.csv",
                        python_env=python_env,
                    )
                    # Clean up
                    os.remove(local_file_path)
                    print(f"Cleaned up: {local_file_path}")
                else:
                    print(f"Failed to download: {blob_name}")
    finally:
        if cleanup_work_dir and os.path.exists(work_dir):
            shutil.rmtree(work_dir)
            print(f"Cleaned up work directory: {work_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="download and do certain functions from gcs"
    )
    parser.add_argument(
        "--bucket_name", help="gcs bucket name you want to download from"
    )
    parser.add_argument("--prefix", help="gcs prefix to your bucket name")
    parser.add_argument(
        "--base-dir", help="directory where you want to download the models"
    )
    parser.add_argument(
        "--inject-pytorch",
        action="store_true",
        help="flag to enable downlaoding and injecting of pypi modules",
    )
    parser.add_argument(
        "--process",
        action="store_true",
        help="download, extract and generate opcodes of files from gcs",
    )
    parser.add_argument(
        "--opensource",
        action="store_true",
        help="download from gcs and run opensource tools",
    )
    parser.add_argument(
        "--trace-and-scan",
        help="trace and run opensource tools on files from gcs after downloading",
    )
    parser.add_argument(
        "--scan_only", action="store_true", help="download and scan from gcs"
    )
    parser.add_argument(
        "--pyenv310", help="path to python environment for modelscan usage"
    )
    parser.add_argument("--extension", help="extension to sscan1")
    parser.add_argument(
        "--inject-obfuscated",
        action="store_true",
        help="inject with obfuscated payloads",
    )
    parser.add_argument(
        "--inject-weights", action="store_true", help="inject with overwritten payloads"
    )
    parser.add_argument(
        "--inject-external", action="store_true", help="inject with external payloads"
    )
    parser.add_argument("--payload-dir", help="directory to get paylaods from")

    args = parser.parse_args()

    if args.inject_pytorch:
        download_and_inject_pytorch(args.bucket_name, args.prefix, args.base_dir)

    if args.inject_obfuscated:
        download_and_inject_obfuscated(
            args.bucket_name, args.payload_dir, args.prefix, args.base_dir
        )
    if args.inject_weights:
        download_and_inject_weights(
            args.bucket_name,
            args.payload_dir,
            args.pyenv310,
            args.prefix,
            args.base_dir,
        )
    if args.inject_external:
        download_and_inject_external(
            args.bucket_name,
            args.payload_dir,
            args.pyenv310,
            args.prefix,
            args.base_dir,
        )
    if args.process:
        process_gcs_files_with_tracing(args.bucket_name, args.prefix, args.base_dir)
    if args.opensource:
        if args.pyenv310:
            download_and_run_opensource(
                args.bucket_name, args.prefix, args.base_dir, args.pyenv310
            )
        else:
            print(
                "Please provide path to python environment with flag --pyenv310 so that modelscan can run"
            )
    if args.trace_and_scan:
        if args.pyenv310:
            trace_and_opensource_gcs(
                args.bucket_name, args.prefix, args.base_dir, args.pyenv310
            )
        else:
            print(
                "Please provide path to python environment with flag --pyenv310 so that modelscan can run"
            )
    if args.scan_only:
        opensource_gcs(args.bucket_name, args.extension, args.prefix, args.base_dir)
