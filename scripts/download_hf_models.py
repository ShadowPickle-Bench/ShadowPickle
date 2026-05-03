import argparse
import datetime
import hashlib
import pickle
import os
import json

HF_ENDPOINT = "https://hf-mirror.com"

os.environ["HF_XET_HIGH_PERFORMANCE"] = "1"
os.environ["HF_ENDPOINT"] = HF_ENDPOINT

from huggingface_hub import HfApi, hf_hub_url, snapshot_download
import pandas as pd
import requests
import zipfile
import shutil
import psutil
from utils import save_model_metadata, upload_to_gcs
import time
import random
from fickle_insertion import load_payloads_from_csv, inject_and_test_single_model
from opensource_runner import do_open_source_checks
from pytorch_injector import (
    pytorch_injector,
    obfuscated_pytorch_injector,
    inject_at_end,
)
from payload_generator import get_random_pkl_file


def run_opensource(file_path, venv):
    return do_open_source_checks(
        file_path,
        f"../Results/results/HF_opensource_result_{args.tag}.csv",
        python_env=venv,
    )


def sha256_file(path, chunk_size=1024 * 1024):  # 1 MB chunks
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def get_last_commit_hash(repo_id, repo_type="model"):
    """
    repo_id: e.g. "bert-base-uncased" or "username/my-dataset"
    repo_type: "model", "dataset", or "space"
    """
    api = HfApi()

    commits = api.list_repo_commits(
        repo_id=repo_id,
        repo_type=repo_type,
    )

    if not commits:
        return None

    return commits[0].commit_id


EXTENSIONS = (
    ".pickle",
    ".pkl",
    ".pt",
    ".pth",
    ".bin",
    ".th",
    ".data",
    ".joblib",
    ".dill",
)

TAG = None
SPACE_LIMIT_GB = 20
SPACE_LIMIT_BYTES = SPACE_LIMIT_GB * 1024 * 1024 * 1024
LIMIT_MATCHES = 10000
api = HfApi()


def get_memory_usage():
    """Get current memory usage in MB"""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / 1024 / 1024


def check_memory_safety(
    estimated_usage_mb, max_memory_gb=32, safety_margin_gb=2, safety_factor=1.5
):
    """
    Check if deserializing the pickle file is safe given memory constraints.
    """
    current_memory_mb = get_memory_usage()

    max_memory_mb = max_memory_gb * 1024
    safety_margin_mb = safety_margin_gb * 1024  # Buffer to avoid OOM errors

    peak_usage_mb = current_memory_mb + estimated_usage_mb * safety_factor
    safe_limit_mb = max_memory_mb - safety_margin_mb

    is_safe = peak_usage_mb <= safe_limit_mb

    return is_safe


def get_security_score(security_status):
    """
    Convert security status from hugging face tools to a numerical score.
    For now each unsafe detection is count as 1 point.
    """
    tools = set(
        ["protectAiScan", "avScan", "pickleImportScan", "jFrogScan", "virusTotalScan"]
    )
    count = {tool: 0 for tool in tools}
    for tool in tools:
        if tool in security_status:
            status = security_status[tool].get("status", "")
            if status == "unsafe":
                count[tool] += 1
    return count


def get_security_info(files, repo_id, tag=None):
    """
    Get security information of hugging face tools on the pytorch_model.bin file
    """
    ENDPOINT = f"{HF_ENDPOINT}/api/models/{repo_id}/tree/main?expand=True"
    res = {}
    try:
        response = requests.get(ENDPOINT)
        data = response.json()
        # isMal = False
        if response.status_code == 200:
            for target_file in files:
                for file_info in data:
                    if target_file in file_info.get("path", ""):
                        security_info = file_info.get("securityFileStatus", {})
                        if security_info.get("status", "") == "unsafe":
                            # isMal = True
                            res[target_file] = {
                                "status": "unsafe",
                                "score": get_security_score(security_info),
                            }
                        else:
                            res[target_file] = {
                                "status": security_info.get("status", "unknown"),
                                "score": {},
                            }
    except Exception as e:
        print(f"Error fetching security info for {repo_id}: {e}")
    return res


def get_remote_file_size(repo_id, filename, repo_type=None):
    try:
        url = hf_hub_url(repo_id=repo_id, filename=filename, repo_type=repo_type)
        response = requests.head(url, allow_redirects=True)
        if response.status_code == 200:
            size = int(response.headers.get("content-length", 0))
            return size
    except Exception as e:
        print(f"Error getting size for {repo_id}/{filename}: {e}")
    return None


def get_directory_size(path):
    """Get the total size of a directory in bytes"""
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if os.path.exists(filepath):
                total_size += os.path.getsize(filepath)
    return total_size


def get_download_size(analysis_type):
    download_count = 0
    total_size = 0

    for model in models:
        if download_count >= LIMIT_MATCHES:
            print(f"\nReached max download limit of {LIMIT_MATCHES}. Stopping.")
            break

        model_id = model.modelId
        try:
            print(f"\nChecking model: {model_id}")
            info = None
            if analysis_type == "model":
                info = api.model_info(model_id)
            elif analysis_type == "dataset":
                info = api.dataset_info(model_id)
            else:
                print("Invalid type. Please try again")
                return
            siblings = info.siblings

            file = None

            for file in siblings:
                pytorch_bin_file = file.rfilename.lower()
                if analysis_type == "model" and pytorch_bin_file == "pytorch_model.bin":
                    file = pytorch_bin_file
                    break
                elif analysis_type == "dataset" and pytorch_bin_file.endswith(".py"):
                    file = pytorch_bin_file
            if not file:
                print("No pytorch_model.bin file found. Skipping this model.")
                continue

            download_count += 1
            size_bytes = get_remote_file_size(model_id, file)
            if size_bytes is not None:
                size_mb = size_bytes / (1024 * 1024)
                total_size += size_mb
                print(f"Size of {file}: {size_mb:.2f} MB")
            else:
                print(f"Could not determine size for {file}")
        except Exception as e:
            print(f"Skipping {model_id} due to error: {e}")

    print(
        f"Total size of all {LIMIT_MATCHES} models would occupy on disk: {total_size}MB"
    )


def extract_and_cleanup(bin_file_path, extract_dir):
    """
    Extract .bin file and clean up, keeping only .bin and .pkl/.pickle files
    Returns True if pickle files were found and extracted successfully
    """
    try:
        with zipfile.ZipFile(bin_file_path, "r") as zip_ref:
            zip_ref.extractall(extract_dir)
            print(f"Extracted contents to: {extract_dir}")

        pkl_files = []
        for root, _, files in os.walk(extract_dir):
            for file in files:
                if (
                    file.endswith(".pkl")
                    or file.endswith(".pickle")
                    or file.endswith(".pt")
                ):
                    pkl_files.append(os.path.join(root, file))

        if not pkl_files:
            print("No .pkl or .pickle files found after extraction.")
            return False

        print(f"Found {len(pkl_files)} pickle files. Cleaning up...")

        bin_filename = os.path.basename(bin_file_path)
        for root, dirs, files in os.walk(extract_dir, topdown=False):
            for file in files:
                fpath = os.path.join(root, file)
                if file != bin_filename:
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


def download_models():
    download_count = 0

    for model in models:
        if download_count >= LIMIT_MATCHES:
            print(f"\nReached max download limit of {LIMIT_MATCHES}. Stopping.")
            break

        model_id = model.modelId
        try:
            print(f"\nChecking model: {model_id}")
            info = api.model_info(model_id)
            siblings = info.siblings

            print("these are siblings", siblings)
            # exit()
            # Look for .bin files first (required for the workflow)
            pytorch_bin_file = None

            for file in siblings:
                pytorch_bin_file = file.rfilename.lower()
                if pytorch_bin_file == "pytorch_model.bin":
                    pytorch_bin_file = pytorch_bin_file
                    break

            if not pytorch_bin_file:
                print("No pytorch_model.bin file found. Skipping this model.")
                continue

            print(f"Found .bin file: {pytorch_bin_file}. Downloading...")
            local_dir = os.path.join(DOWNLOAD_DIR, model_id.replace("/", "__"))

            # Download the .bin file
            snapshot_download(
                repo_id=model_id,
                allow_patterns=[pytorch_bin_file],
                local_dir=local_dir,
                local_dir_use_symlinks=False,
            )

            bin_path = os.path.join(local_dir, pytorch_bin_file)

            # Try to extract and find pickle files
            success = extract_and_cleanup(bin_path, local_dir)

            if success:
                print(f"Successfully processed {model_id}")
                print(f"   - Kept .bin file: {bin_path}")
                print(f"   - Extracted pickle files")
                print(f"   - Cleaned up other files")
                download_count += 1
            else:
                print(
                    f"Could not extract pickle files from {model_id}. Removing the folder"
                )
                shutil.rmtree(local_dir)

        except Exception as e:
            print(f"Skipping {model_id} due to error: {e}")

    print(f"\nSuccessfully downloaded and processed {download_count} models.")


def get_cycled_payload(final_list, payload_mapping, total_injections):
    """Get the next payload in cycle"""
    if not final_list:
        return None, None, {}

    current_payload_index = total_injections % len(final_list)
    payload = final_list[current_payload_index]
    cycle_number = total_injections // len(final_list) + 1
    position_in_cycle = (total_injections % len(final_list)) + 1

    payload_info = {
        "payload_index": current_payload_index,
        "cycle_number": cycle_number,
        "position_in_cycle": position_in_cycle,
        "total_injection_number": total_injections,
    }

    return payload, current_payload_index, payload_info


def download_and_upload_injected(
    download_dir,
    space_limit_bytes,
    TAG,
    explored_models,
    download_log_df,
    limit,
    direction="desc",
    gcs_bucket_name=None,
    models_to_download=[],
):
    """Modified download function that injects payloads immediately after each download and uploads to GCS."""

    final_list, payload_mapping = load_payloads_from_csv("../malhug_result_info.csv")
    payload_index = 0
    total_injections = 0

    print(f"Loaded {len(final_list)} payloads")
    if models_to_download == []:
        if TAG is None:
            models = list(api.list_models(sort="likes"))
        else:
            models = list(api.list_models(filter=TAG, sort="likes"))
    else:
        models = models_to_download
    if direction == "asc":
        models = list(reversed(models))

    model_ids = [model.id for model in models]

    # Find the index of the target model
    # uncomment if you want to download froma  particular model index
    # target_model = "McGill-NLP/tapas-statcan-large-metadata_encoder-title"
    #
    # try:
    #     index = model_ids.index(target_model)
    #     print(f"Index of '{target_model}': {index}")
    #
    # except ValueError:
    #     print(f"Model '{target_model}' not found.")
    #     # models.index("teven/cross_all_bs192_hardneg_finetuned_WebNLG2020_relevance")
    #     index = 0

    index = 0
    downloaded_models = []
    injection_results = []
    current_size = 0
    i = 0
    fail_count = 0
    start = index

    if not download_log_df.empty:
        last_download = download_log_df.iloc[-1]["name"]
        for model in models:
            i += 1
            if model.modelId == last_download:
                start = i + 1
                break

    for j in range(start, len(models)):
        model_id = models[j].modelId
        if "TransQuest" in model_id:
            continue
        if total_injections >= 8:
            break
        if len(explored_models) + len(downloaded_models) >= limit:
            print(f"{limit} models have been downloaded")
            break

        if model_id in explored_models and direction == "asc":
            print("Encountered an already explored model in the wild run. Stopping.")
            break

        i += 1
        if model_id in explored_models:
            print(f"Skipping already explored model: {model_id}")
            continue

        try:
            print(f"\nChecking model: {model_id}")
            time.sleep(random.uniform(0.2, 0.75))
            info = api.model_info(model_id)
            siblings = info.siblings

            pytorch_bin_file = next(
                (
                    file.rfilename
                    for file in siblings
                    if file.rfilename.lower() == "pytorch_model.bin"
                ),
                None,
            )

            if not pytorch_bin_file:
                print("No pytorch_model.bin file found. Skipping this model.")
                continue

            file_size = get_remote_file_size(model_id, pytorch_bin_file)
            if file_size is None:
                print(
                    f"Skipping model. Could not determine size for {pytorch_bin_file}"
                )
                continue

            if file_size * 2 > space_limit_bytes:
                print(
                    f"Adding {model_id} would exceed space limit. Stopping downloads."
                )
                break

            file_size_mb = file_size / (1024 * 1024)
            is_safe = check_memory_safety(
                file_size_mb, max_memory_gb=32, safety_margin_gb=2, safety_factor=1.5
            )

            if not is_safe:
                print(
                    f"Memory safety check failed for {model_id} with size {file_size_mb}. Skipping download."
                )
                continue

            print(f"Found .bin file: {pytorch_bin_file}. Size: {file_size_mb:.2f} MB")
            local_dir = os.path.join(download_dir, model_id.replace("/", "__"))

            pytorch_bfile = os.path.join(local_dir, "pytorch_model.bin")
            if os.path.exists(pytorch_bfile):
                print(f"Model {model_id} found in cache. Skipping download.")
                actual_size = get_directory_size(local_dir)
                current_size += actual_size
                downloaded_models.append(model_id)
                continue

            snapshot_download(
                repo_id=model_id,
                allow_patterns=[pytorch_bin_file],
                local_dir=local_dir,
                local_dir_use_symlinks=False,
            )

            bin_path = os.path.join(local_dir, pytorch_bin_file)
            try:
                do_open_source_checks(bin_path, f"{TAG}_opensource_results.csv")
            except zipfile.BadZipFile:
                print("Not a zip archive.")
            except Exception as e:
                print(f"Extraction error: {e}")

            success = extract_and_cleanup(bin_path, local_dir)

            if success:
                actual_size = get_directory_size(local_dir)
                current_size += actual_size
                download_log_df.loc[len(download_log_df)] = {
                    "name": model_id,
                    "likes": info.likes,
                    "downloads": info.downloads,
                }
                downloaded_models.append(model_id)

                download_log_file_name = (
                    f"wild_{TAG}_downloaded_models.csv"
                    if direction == "asc"
                    else f"{TAG}_downloaded_models.csv"
                )
                save_model_metadata(
                    [download_log_df],
                    [
                        os.path.join(
                            os.path.dirname(download_dir), download_log_file_name
                        )
                    ],
                )

                print(f"Successfully processed {model_id}")
                print(f"   - Actual size: {actual_size / (1024 * 1024):.2f} MB")
                print(
                    f"   - Total size so far: {current_size / (1024 * 1024 * 1024):.2f} GB"
                )
                print(f"Saved CSV file containing model metadata")

                #
            else:
                print(
                    f"Could not extract pickle files from {model_id}. Removing the folder"
                )
                shutil.rmtree(local_dir)
        except Exception as e:
            print(f"Skipping {model_id} due to error: {e}")
            continue

        try:
            model_path = os.path.join(local_dir, "pytorch_model.bin")

            if os.path.exists(model_path):
                payload, current_payload_index, payload_info = get_cycled_payload(
                    final_list, payload_mapping, total_injections
                )

                if current_payload_index == 0 and total_injections > 0:
                    print(f"Starting new payload cycle #{payload_info['cycle_number']}")

                print(f"Injecting payload into {model_id}...")
                injection_count = 0

                while True:
                    print(
                        f"Using payload [{current_payload_index}] (Cycle {payload_info['cycle_number']}, Position {payload_info['position_in_cycle']}/{len(final_list)})"
                    )
                    total_injections += injection_count
                    payload, current_payload_index, payload_info = get_cycled_payload(
                        final_list, payload_mapping, total_injections
                    )

                    injection_success, load_success, injected_model_path = (
                        inject_and_test_single_model(
                            model_path,
                            current_payload_index,
                            payload,
                            payload_mapping,
                            f"{TAG}_injection.csv",
                        )
                    )

                    total_injections -= injection_count
                    if not injection_success or not load_success:
                        injection_count += 1
                        fail_count += 1
                        if fail_count > 5:
                            break
                        continue
                    else:
                        break

                injection_results.append(
                    {
                        "model_id": model_id,
                        **payload_info,
                        "injection_success": injection_success,
                        "load_success": load_success,
                    }
                )

                total_injections += 1
                print(f"Total injections so far: {total_injections}")

                if injection_success and gcs_bucket_name:
                    base_blob_path = f"injected_models/feature_extraction/{model_id.replace('/', '__')}"
                    original_blob_name = f"{base_blob_path}/pytorch_model.bin"
                    injected_blob_name = f"{base_blob_path}/pytorch_model_injected.bin"

                    upload_to_gcs(model_path, gcs_bucket_name, original_blob_name)

                    upload_to_gcs(
                        injected_model_path, gcs_bucket_name, injected_blob_name
                    )

                downloaded_models.append(model_id)
                shutil.rmtree(local_dir)
                print(total_injections)
        except Exception as e:
            print(f"Error processing {model_id}: {e}")

    total_cycles_completed = total_injections // len(final_list)
    remaining_in_current_cycle = total_injections % len(final_list)

    print(f"\nInjection Summary:")
    print(f"   Total models downloaded: {len(downloaded_models)}")
    print(f"   Total injections performed: {total_injections}")
    print(f"   Complete payload cycles: {total_cycles_completed}")
    print(f"   Payloads used in current cycle: {remaining_in_current_cycle}")

    return downloaded_models, injection_results


def download_models_with_immediate_injection(
    download_dir,
    space_limit_bytes,
    TAG,
    explored_models,
    download_log_df,
    limit,
    direction="desc",
):
    """Modified download function that injects payloads immediately after each download"""

    final_list, payload_mapping = load_payloads_from_csv("../malhug_result_info.csv")
    payload_index = 0
    total_injections = 0  # Track total number of injections for cycling

    print(f"Loaded {len(final_list)} payloads")

    models = list(api.list_models(filter=TAG, sort="likes"))
    if direction == "asc":
        models = list(reversed(models))

    downloaded_models = []
    injection_results = []
    current_size = 0

    downloaded_models = []
    current_size = 0
    i = 0
    start = 0

    # Resuming from last successful download
    if not download_log_df.empty:
        last_download = download_log_df.iloc[-1]["name"]
        for model in models:
            i += 1
            if model.modelId == last_download:
                start = i + 1
                break

    for j in range(start, len(models)):
        model_id = models[j].modelId
        if len(explored_models) + len(downloaded_models) >= limit:
            print(f"{limit} models have been downloaded")
            break

        # If it is a wild run, we are going in the opposite direction
        # If an already explored model is encountered, we break the loop
        # since it means we are moving into the benign set the model is trained on
        if model_id in explored_models and direction == "asc":
            print("Encountered an already explored model in the wild run. Stopping.")
            break

        i += 1
        if model_id in explored_models:
            print(f"Skipping already explored model: {model_id}")
            actual_size = get_directory_size(local_dir)
            current_size += actual_size
            continue

        try:
            print(f"\nChecking model: {model_id}")
            time.sleep(random.uniform(0.2, 0.75))
            info = api.model_info(model_id)
            siblings = info.siblings

            pytorch_bin_file = None
            for file in siblings:
                pytorch_bin_file = file.rfilename.lower()
                if pytorch_bin_file == "pytorch_model.bin":
                    pytorch_bin_file = pytorch_bin_file
                    break

            if not pytorch_bin_file:
                print("No pytorch_model.bin file found. Skipping this model.")
                continue

            file_size = get_remote_file_size(model_id, pytorch_bin_file)
            if file_size is None:
                print(
                    f"Skipping model. Could not determine size for {pytorch_bin_file}"
                )
                continue

            if current_size + file_size > space_limit_bytes:
                print(
                    f"Adding {model_id} would exceed space limit. Stopping downloads."
                )
                break

            file_size_mb = file_size / (1024 * 1024)
            is_safe = check_memory_safety(
                file_size_mb, max_memory_gb=32, safety_margin_gb=2, safety_factor=1.5
            )  # Checking for possible OOM errors

            if not is_safe:
                print(
                    f"Memory safety check failed for {model_id} with size {file_size_mb}. Skipping download."
                )
                continue

            print(f"Found .bin file: {pytorch_bin_file}. Size: {file_size_mb:.2f} MB")
            local_dir = os.path.join(download_dir, model_id.replace("/", "__"))

            pytorch_bfile = os.path.join(local_dir, "pytorch_model.bin")
            if os.path.exists(pytorch_bfile):
                print(f"Model {model_id} found in cache. Skipping download.")
                actual_size = get_directory_size(local_dir)
                current_size += actual_size
                downloaded_models.append(model_id)
                continue

            snapshot_download(
                repo_id=model_id,
                allow_patterns=[pytorch_bin_file],
                local_dir=local_dir,
                local_dir_use_symlinks=False,
            )

            bin_path = os.path.join(local_dir, pytorch_bin_file)

            success = extract_and_cleanup(bin_path, local_dir)

            if success:
                actual_size = get_directory_size(local_dir)
                current_size += actual_size
                download_log_df.loc[len(download_log_df)] = {
                    "name": model_id,
                    "likes": info.likes,
                    "downloads": info.downloads,
                }
                downloaded_models.append(model_id)
                download_log_file_name = (
                    f"wild_{TAG}_downloaded_models.csv"
                    if direction == "asc"
                    else f"{TAG}_downloaded_models.csv"
                )
                save_model_metadata(
                    [download_log_df],
                    [
                        os.path.join(
                            os.path.dirname(download_dir), download_log_file_name
                        )
                    ],
                )
                print(f"Successfully processed {model_id}")
                print(f"   - Actual size: {actual_size / (1024 * 1024):.2f} MB")
                print(
                    f"   - Total size so far: {current_size / (1024 * 1024 * 1024):.2f} GB"
                )
                print(f"Saved CSV file containing model metadata")

            else:
                print(
                    f"Could not extract pickle files from {model_id}. Removing the folder"
                )
                shutil.rmtree(local_dir)
        except Exception as e:
            print(f"Skipping {model_id} due to error: {e}")
            continue

        try:
            model_path = os.path.join(local_dir, "pytorch_model.bin")

            if os.path.exists(model_path):
                payload, current_payload_index, payload_info = get_cycled_payload(
                    final_list, payload_mapping, total_injections
                )

                if current_payload_index == 0 and total_injections > 0:
                    print(f"Starting new payload cycle #{payload_info['cycle_number']}")

                print(f"Injecting payload into {model_id}...")
                print(
                    f"Using payload [{current_payload_index}] (Cycle {payload_info['cycle_number']}, Position {payload_info['position_in_cycle']}/{len(final_list)})"
                )

                injection_success, load_success = inject_and_test_single_model(
                    model_path, current_payload_index, payload, payload_mapping
                )

                injection_results.append(
                    {
                        "model_id": model_id,
                        **payload_info,  # Include all payload cycling info
                        "injection_success": injection_success,
                        "load_success": load_success,
                    }
                )

                total_injections += 1
                print(f"Total injections so far: {total_injections}")

            downloaded_models.append(model_id)
            shutil.rmtree(local_dir)

        except Exception as e:
            print(f"Error processing {model_id}: {e}")

    # Summary statistics
    total_cycles_completed = total_injections // len(final_list)
    remaining_in_current_cycle = total_injections % len(final_list)

    print(f"\nInjection Summary:")
    print(f"   Total models downloaded: {len(downloaded_models)}")
    print(f"   Total injections performed: {total_injections}")
    print(f"   Complete payload cycles: {total_cycles_completed}")
    print(f"   Payloads used in current cycle: {remaining_in_current_cycle}")

    return downloaded_models, injection_results


def download_models_with_space_limit(
    download_dir,
    space_limit_bytes,
    TAG,
    explored_models,
    download_log_df,
    limit,
    direction="desc",
):
    """
    Download models within the specified space limit
    """
    models = None
    models = list(api.list_models(filter=TAG, sort="likes"))
    if direction == "asc":
        models = list(reversed(models))
    print(f"Found {len(models)} models with tag '{TAG}'")

    downloaded_models = []
    current_size = 0
    i = 0
    start = 12533
    print(models)
    # exit()

    # Resuming from last successful download
    if not download_log_df.empty:
        last_download = download_log_df.iloc[-1]["name"]
        for model in models:
            i += 1
            if model.modelId == last_download:
                start = i + 1
                break

    for j in range(start, len(models)):
        model_id = models[j].modelId
        if len(explored_models) + len(downloaded_models) >= limit:
            print(f"{limit} models have been downloaded")
            break

        # If it is a wild run, we are going in the opposite direction
        # If an already explored model is encountered, we break the loop
        # since it means we are moving into the benign set the model is trained on
        if model_id in explored_models and direction == "asc":
            print("Encountered an already explored model in the wild run. Stopping.")
            break

        i += 1
        if model_id in explored_models:
            print(f"Skipping already explored model: {model_id}")
            actual_size = get_directory_size(local_dir)
            current_size += actual_size
            continue

        try:
            print(f"\nChecking model: {model_id}")
            time.sleep(random.uniform(0.2, 0.75))
            info = api.model_info(model_id)
            siblings = info.siblings

            pytorch_bin_file = None
            for file in siblings:
                pytorch_bin_file = file.rfilename.lower()
                if pytorch_bin_file == "pytorch_model.bin":
                    pytorch_bin_file = pytorch_bin_file
                    break

            if not pytorch_bin_file:
                print("No pytorch_model.bin file found. Skipping this model.")
                continue

            file_size = get_remote_file_size(model_id, pytorch_bin_file)
            if file_size is None:
                print(
                    f"Skipping model. Could not determine size for {pytorch_bin_file}"
                )
                continue

            if current_size + file_size > space_limit_bytes:
                print(
                    f"Adding {model_id} would exceed space limit. Stopping downloads."
                )
                continue

            file_size_mb = file_size / (1024 * 1024)
            is_safe = check_memory_safety(
                file_size_mb, max_memory_gb=32, safety_margin_gb=2, safety_factor=1.5
            )  # Checking for possible OOM errors

            if not is_safe:
                print(
                    f"Memory safety check failed for {model_id} with size {file_size_mb}. Skipping download."
                )
                continue

            print(f"Found .bin file: {pytorch_bin_file}. Size: {file_size_mb:.2f} MB")
            local_dir = os.path.join(download_dir, model_id.replace("/", "__"))
            pytorch_bfile = os.path.join(local_dir, "pytorch_model.bin")
            if os.path.exists(pytorch_bfile):
                print(f"Model {model_id} found in cache. Skipping download.")
                actual_size = get_directory_size(local_dir)
                current_size += actual_size
                downloaded_models.append(model_id)
                continue

            snapshot_download(
                repo_id=model_id,
                allow_patterns=[pytorch_bin_file],
                local_dir=local_dir,
                local_dir_use_symlinks=False,
            )

            bin_path = os.path.join(local_dir, pytorch_bin_file)

            success = extract_and_cleanup(bin_path, local_dir)

            if success:
                actual_size = get_directory_size(local_dir)
                current_size += actual_size
                download_log_df.loc[len(download_log_df)] = {
                    "name": model_id,
                    "likes": info.likes,
                    "downloads": info.downloads,
                }
                downloaded_models.append(model_id)
                download_log_file_name = (
                    f"wild_{TAG}_downloaded_models.csv"
                    if direction == "asc"
                    else f"{TAG}_downloaded_models.csv"
                )
                save_model_metadata(
                    [download_log_df],
                    [
                        os.path.join(
                            os.path.dirname(download_dir), download_log_file_name
                        )
                    ],
                )
                print(f"Successfully processed {model_id}")
                print(f"   - Actual size: {actual_size / (1024 * 1024):.2f} MB")
                print(
                    f"   - Total size so far: {current_size / (1024 * 1024 * 1024):.2f} GB"
                )
                print(f"Saved CSV file containing model metadata")

            else:
                print(
                    f"Could not extract pickle files from {model_id}. Removing the folder"
                )
                shutil.rmtree(local_dir)
        except Exception as e:
            print(f"Skipping {model_id} due to error: {e}")

    print(f"\nSuccessfully downloaded and processed {len(downloaded_models)} models.")
    print(f"Total space used: {current_size / (1024 * 1024 * 1024):.2f} GB")

    return downloaded_models, i


def download_datasets():
    datasets = list(api.list_datasets(filter=TAG, limit=500, sort="likes"))
    print(f"Found {len(datasets)} datasets with tag '{TAG}'")
    filtered_datasets = []
    for dataset in datasets:
        dataset_id = dataset.id
        try:
            print(f"\nChecking dataset: {dataset_id}")
            info = api.dataset_info(dataset_id)
            siblings = info.siblings

            for file in siblings:
                pytorch_bin_file = file.rfilename.lower()
                if pytorch_bin_file.endswith(".py"):
                    size_bytes = get_remote_file_size(
                        dataset_id, pytorch_bin_file, repo_type="dataset"
                    )
                    if size_bytes is None:
                        continue
                    size_mb = size_bytes / (1024 * 1024)
                    print(f"Found file: {pytorch_bin_file} - Size: {size_mb:.2f} MB")
                    if size_mb <= SPACE_LIMIT_GB * 1024:
                        filtered_datasets.append(
                            (dataset_id, pytorch_bin_file, size_mb)
                        )
                        print(
                            f"✔ Added: {dataset_id}/{pytorch_bin_file} ({size_mb:.2f} MB)"
                        )
                        break

            if len(filtered_datasets) >= LIMIT_MATCHES:
                break

        except Exception as e:
            print(f"⚠️ Skipping {dataset_id} due to error: {e}")
            continue

    print(f"\n{len(filtered_datasets)} datasets passed the filter.")

    for dataset_id, filename, size_mb in filtered_datasets:
        print(f"Downloading {dataset_id}/{filename} ({size_mb:.2f} MB)...")
        snapshot_download(
            repo_id=dataset_id,
            repo_type="dataset",
            allow_patterns=[filename],
            local_dir=os.path.join(
                DOWNLOAD_DIR, "dataset", dataset_id.replace("/", "__")
            ),
            local_dir_use_symlinks=False,
        )


def download_and_scan(
    download_dir,
    space_limit_bytes,
    TAG,
    explored_models,
    download_log_df,
    limit,
    pyvenv,
    direction="desc",
    mode=None,
    models_to_download=[],
):
    """Modified download function that injects payloads immediately after each download and uploads to GCS."""

    if models_to_download == []:
        if TAG is None:
            models = list(api.list_models(sort="likes"))
        else:
            models = list(api.list_models(filter=TAG, sort="likes"))
    else:
        models = models_to_download
    if direction == "asc":
        models = list(reversed(models))

    # model_ids = [model.id for model in models]

    # Find the index of the target model
    # uncomment if you want to download froma  particular model index
    # target_model = "csebuetnlp/banglat5_nmt_en_bn"
    #
    # try:
    #     index = model_ids.index(target_model)
    #     print(f"Index of '{target_model}': {index}")
    # except ValueError:
    #     print(f"Model '{target_model}' not found.")
    #     models.index("csebuetnlp/banglat5_nmt_en_bn")

    index = 0
    downloaded_models = []
    current_size = 0
    i = 0
    start = index
    end = len(models)

    if not download_log_df.empty:
        last_download = download_log_df.iloc[-1]["name"]
        for model in models:
            i += 1
            if model.modelId == last_download:
                start = i + 1
                break

    print(f"Starting from {start} in the list of models")

    print(f"Found {end} models from HF API to crawl!")

    match mode:
        case "first_half":
            end = (start + end) // 2
            print(
                f"Choosing the first half mode and setting the end of the for loop to {end}"
            )
        case "second_half":
            start = (start + end) // 2
            print(
                f"Choosing the second half mode and setting the start of the for loop to {start}"
            )
        case None:
            print(f"Going with the default mode with start={start} and end={end}")
        case _:
            print("Wrong mode mentioned.")
            exit()

    for j in range(start, end):
        model_id = models[j].modelId
        if model_id in explored_models and direction == "asc":
            print("Encountered an already explored model in the wild run. Stopping.")
            break

        print(f"Current iteration is {j}")

        if model_id in explored_models:
            print(f"Skipping already explored model: {model_id}")
            continue

        local_dir = ""
        try:
            print(f"\nChecking model: {model_id}")
            time.sleep(random.uniform(0.2, 0.75))
            info = api.model_info(model_id)
            siblings = info.siblings

            # print(siblings)
            # print("that was sibblings")
            # exit()
            matched_files = []
            for file in siblings:
                # print(file)
                filename = file.rfilename

                # split extension safely

                if filename.endswith(EXTENSIONS):
                    matched_files.append(filename)
            # print(matched_files)
            # exit()

            security_info = get_security_info(matched_files, model_id)
            print("This is the security info: ", security_info)

            for pytorch_bin_file in matched_files:
                print("checking for file: ", pytorch_bin_file)
                # exit()
                if not pytorch_bin_file:
                    print("No pytorch_model.bin file found. Skipping this model.")
                    continue

                file_size = get_remote_file_size(model_id, pytorch_bin_file)
                if file_size is None:
                    print(
                        f"Skipping model. Could not determine size for {pytorch_bin_file}"
                    )
                    continue

                if file_size > space_limit_bytes:
                    print(
                        f"Adding {model_id} would exceed space limit. Stopping downloads."
                    )
                    break

                file_size_mb = file_size / (1024 * 1024)
                is_safe = check_memory_safety(
                    file_size_mb,
                    max_memory_gb=32,
                    safety_margin_gb=2,
                    safety_factor=2,
                )

                if not is_safe:
                    print(
                        f"Memory safety check failed for {model_id} with size {file_size_mb}. Skipping download."
                    )
                    continue

                print(
                    f"Found .bin file: {pytorch_bin_file}. Size: {file_size_mb:.2f} MB"
                )
                local_dir = os.path.join(download_dir, model_id.replace("/", "__"))

                pytorch_bfile = os.path.join(local_dir, pytorch_bin_file)
                if os.path.exists(pytorch_bfile):
                    print(f"Model {model_id} found in cache. Skipping download.")
                    actual_size = get_directory_size(local_dir)
                    current_size += actual_size
                    downloaded_models.append(model_id)
                    continue

                snapshot_download(
                    repo_id=model_id,
                    allow_patterns=[pytorch_bin_file],
                    local_dir=local_dir,
                )

                bin_path = os.path.join(local_dir, pytorch_bin_file)
                try:
                    number_of_detctions = run_opensource(bin_path, pyvenv)
                    # do_open_source_checks(
                    #     bin_path, "no_cluster_benign_set_opensource_results.csv"
                    # )
                except zipfile.BadZipFile:
                    print("Not a zip archive.")
                    number_of_detctions = 0
                except Exception as e:
                    print(f"Extraction error: {e}")
                    number_of_detctions = 0

                success = extract_and_cleanup(bin_path, local_dir)

                protectAI = (
                    security_info.get(pytorch_bin_file, {})
                    .get("score", {})
                    .get("protectAiScan", 0)
                )
                picklescan = (
                    security_info.get(pytorch_bin_file, {})
                    .get("score", {})
                    .get("pickleImportScan", 0)
                )
                jfrogscan = (
                    security_info.get(pytorch_bin_file, {})
                    .get("score", {})
                    .get("jFrogScan", 0)
                )
                virusTotal = (
                    security_info.get(pytorch_bin_file, {})
                    .get("score", {})
                    .get("virusTotalScan", 0)
                )
                clamAVScan = (
                    security_info.get(pytorch_bin_file, {})
                    .get("score", {})
                    .get("avScan", 0)
                )

                print(f"HF PickleScan results: {picklescan}")
                print(f"HF JFrog results: {jfrogscan}")
                print(f"HF protectAiScan results: {protectAI}")
                print(f"HF virusTotalScan results: {virusTotal}")
                print(f"HF clamAVScan results: {clamAVScan}")

                number_of_detctions += (
                    protectAI + picklescan + jfrogscan + virusTotal + clamAVScan
                )

                if success:
                    actual_size = get_directory_size(local_dir)
                    last_commit = get_last_commit_hash(model_id)
                    file_hash = sha256_file(bin_path)
                    file_size = (
                        os.path.getsize(bin_path) if os.path.exists(bin_path) else 0
                    )
                    current_size += actual_size
                    kept = number_of_detctions >= 2
                    download_log_df.loc[len(download_log_df)] = {
                        "name": model_id,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "repository": model_id,
                        "likes": info.likes,
                        "downloads": info.downloads,
                        "date_posted": info.created_at,
                        "last_commit": last_commit,
                        "file_hash": file_hash,
                        "file_name": bin_path.split("/")[-1],
                        "file_size_bytes": file_size,
                        "number_of_detctions": number_of_detctions,
                        "detection_threshold_met": kept,
                        "protectAiScan": protectAI,
                        "avScan": clamAVScan,
                        "pickleImportScan": picklescan,
                        "jFrogScan": jfrogscan,
                        "virusTotalScan": virusTotal,
                    }
                    downloaded_models.append(model_id)

                    download_log_file_name = (
                        f"wild_{TAG}_downloaded_models.csv"
                        if direction == "asc"
                        else f"{TAG}_downloaded_models.csv"
                    )

                    # filename to save scan logs in
                    download_log_save_name = os.path.join(
                        download_dir, download_log_file_name
                    )
                    print(download_log_df)
                    print(download_dir)
                    print(download_log_save_name)

                    save_model_metadata(
                        [download_log_df],
                        [download_log_save_name],
                    )

                    print(f"Successfully processed {model_id}")
                    print(f"   - Actual size: {actual_size / (1024 * 1024):.2f} MB")
                    print(
                        f"   - Total size so far: {current_size / (1024 * 1024 * 1024):.2f} GB"
                    )

                else:
                    print(
                        f"Could not extract pickle files from {model_id}. Removing the folder"
                    )

                shutil.rmtree(local_dir)

        except Exception as e:
            print(f"Skipping {model_id} due to error: {e}")
            if os.path.exists(local_dir):
                shutil.rmtree(local_dir)
            continue

    print(f"Total models downloaded: {len(downloaded_models)}")

    return downloaded_models


def download_hf_inject_all_and_upload(
    download_dir,
    space_limit_bytes,
    TAG,
    explored_models,
    download_log_df,
    limit,
    payload_dir,
    gcs_bucket_name,
    direction="desc",
    models_to_download=[],
):
    """
    Downloads pytorch_model.bin from HuggingFace, produces five variants,
    and uploads all of them to GCS:

      1. pytorch_model.bin                                   — original
      2. pytorch_model_injected_{name}_weights_bypass.bin    — overwritte-module
      3. pytorch_model_injected.bin                          — baseline fickling
      4. pytorch_model_injected_pypi.bin                     — pypi
      5. pytorch_model_injected_{name}_external.bin          — external
    """
    final_list, payload_mapping = load_payloads_from_csv("../malhug_result_info.csv")
    total_injections = 0
    fail_count = 0
    print(f"Loaded {len(final_list)} cycled payloads")

    if models_to_download:
        models = models_to_download
    elif TAG is None:
        models = list(api.list_models(sort="likes"))
    else:
        models = list(api.list_models(filter=TAG, sort="likes"))

    if direction == "asc":
        models = list(reversed(models))

    model_ids = [model.id for model in models]
    # Find the index of the target model
    # uncomment if you want to download froma  particular model index
    target_model = "astrobreazy/DialoGPT-small-harrypotter"
    #
    try:
        index = model_ids.index(target_model)
        print(f"Index of '{target_model}': {index}")

    except ValueError:
        print(f"Model '{target_model}' not found.")
        # models.index("teven/cross_all_bs192_hardneg_finetuned_WebNLG2020_relevance")
        index = 0

    downloaded_models = []
    injection_results = []
    current_size = 0
    start = index

    if not download_log_df.empty:
        last_download = download_log_df.iloc[-1]["name"]
        for i, model in enumerate(models):
            if model.modelId == last_download:
                start = i + 1
                break

    for j in range(start, len(models)):
        model_id = models[j].modelId

        if "TransQuest" in model_id:
            continue
        if total_injections >= 8:
            break
        if len(explored_models) + len(downloaded_models) >= limit:
            print(f"{limit} models downloaded, stopping.")
            break
        if model_id in explored_models and direction == "asc":
            print("Encountered already-explored model in wild run. Stopping.")
            break
        if model_id in explored_models:
            print(f"Skipping already explored: {model_id}")
            continue

        try:
            print(f"\nChecking model: {model_id}")
            time.sleep(random.uniform(0.2, 0.75))
            info = api.model_info(model_id)

            pytorch_bin_file = next(
                (
                    f.rfilename
                    for f in info.siblings
                    if f.rfilename.lower() == "pytorch_model.bin"
                ),
                None,
            )
            if not pytorch_bin_file:
                print("No pytorch_model.bin found. Skipping.")
                continue

            file_size = get_remote_file_size(model_id, pytorch_bin_file)
            if file_size is None:
                print(f"Could not determine size. Skipping {model_id}.")
                continue
            if file_size * 2 > space_limit_bytes:
                print("Would exceed space limit. Stopping.")
                break

            file_size_mb = file_size / (1024 * 1024)
            if not check_memory_safety(
                file_size_mb, max_memory_gb=32, safety_margin_gb=2, safety_factor=1.5
            ):
                print(f"Memory safety check failed for {model_id}. Skipping.")
                continue

            local_dir = os.path.join(download_dir, model_id.replace("/", "__"))
            model_path = os.path.join(local_dir, "pytorch_model.bin")

            if os.path.exists(model_path):
                print(f"Cached: {model_id}. Skipping re-download.")
                current_size += get_directory_size(local_dir)
                downloaded_models.append(model_id)
                continue

            print(f"Downloading {model_id} ({file_size_mb:.2f} MB)...")
            snapshot_download(
                repo_id=model_id,
                allow_patterns=[pytorch_bin_file],
                local_dir=local_dir,
                local_dir_use_symlinks=False,
            )

            try:
                do_open_source_checks(model_path, "benign_hf_opensource_results.csv")
            except Exception as e:
                print(f"Open-source check error on original: {e}")

            if not extract_and_cleanup(model_path, local_dir):
                print(f"Could not extract pickle files from {model_id}. Removing.")
                shutil.rmtree(local_dir)
                continue

            current_size += get_directory_size(local_dir)
            download_log_df.loc[len(download_log_df)] = {
                "name": model_id,
                "likes": info.likes,
                "downloads": info.downloads,
            }

        except Exception as e:
            print(f"Download error for {model_id}: {e}")
            continue

        base_blob_path = f"injected_models/{TAG}/{model_id.replace('/', '__')}"

        weights_bypass_path = None
        weights_bypass_blob = None
        external_path = None
        external_blob = None
        injected_model_path = None
        pypi_path = None
        pypi_blob = None

        try:
            # weights
            payload_file = get_random_pkl_file(
                payload_dir + "/overwritten_payloads_exec"
            )
            payload_name = str(payload_file).split("/")[-1].rsplit(".", 1)[0]
            weights_bypass_path = os.path.join(
                local_dir,
                f"pytorch_model_injected_{payload_name}_weights_bypass.bin",
            )
            inject_success_bypass = inject_at_end(
                model_path,
                weights_bypass_path,
                payload_file,
                "injection_log_pytorch_weights_bypass.csv",
            )
            if inject_success_bypass:
                do_open_source_checks(
                    weights_bypass_path,
                    "weights_bypass_opensource_results.csv",
                )
                weights_bypass_blob = (
                    f"{base_blob_path}/"
                    f"pytorch_model_injected_{payload_name}_weights_bypass.bin"
                )
            else:
                print(f"inject_at_end failed for {model_id}.")
                weights_bypass_path = None

            inject_success_cycled = False
            load_success = False
            payload_info = {}

            # fickling baseline
            while True:
                payload, current_payload_index, payload_info = get_cycled_payload(
                    final_list, payload_mapping, total_injections
                )
                print(
                    f"Cycled payload [{current_payload_index}] "
                    f"(Cycle {payload_info['cycle_number']}, "
                    f"pos {payload_info['position_in_cycle']}/{len(final_list)})"
                )
                inject_success_cycled, load_success, injected_model_path = (
                    inject_and_test_single_model(
                        model_path,
                        current_payload_index,
                        payload,
                        payload_mapping,
                        f"{TAG}_injection.csv",
                    )
                )
                if not inject_success_cycled or not load_success:
                    fail_count += 1
                    if fail_count > 5:
                        print("Too many cycled-payload failures. Giving up.")
                        break
                    continue
                else:
                    total_injections += 1
                    print(f"Total cycled injections so far: {total_injections}")
                    break

            # PypI
            pypi_payload_file = get_random_pkl_file(payload_dir)

            pypi_payload_name = str(pypi_payload_file).split("/")[-1].rsplit(".", 1)[0]
            pypi_path = os.path.join(
                local_dir,
                f"pytorch_model_injected_{pypi_payload_name}_pypi.bin",
            )
            inject_success_pypi = pytorch_injector(
                model_path,
                pypi_path,
                pypi_payload_name,
                "pypi_opensource_results.csv",
            )
            if inject_success_pypi:
                do_open_source_checks(
                    pypi_path,
                    "opensource_pypi_results.csv",
                    "./.venv/bin/activate",
                )
                pypi_bypass_blob = (
                    f"{base_blob_path}/"
                    f"pytorch_model_injected_{pypi_payload_name}_pypi.bin"
                )

            else:
                print(f"Pypi injection  failed for {model_id}.")
                pypi_path = None

            # External
            ext_payload_file = get_random_pkl_file(payload_dir + "/external")
            ext_payload_name = str(ext_payload_file).split("/")[-1].rsplit(".", 1)[0]
            external_path = os.path.join(
                local_dir,
                f"pytorch_model_injected_{ext_payload_name}_external.bin",
            )
            inject_success_external = pytorch_injector(
                model_path,
                external_path,
                ext_payload_file,
                "injection_log_pytorch_external.csv",
            )
            if inject_success_external:
                do_open_source_checks(
                    external_path,
                    "external_opensource_results.csv",
                )
                external_blob = (
                    f"{base_blob_path}/"
                    f"pytorch_model_injected_{ext_payload_name}_external.bin"
                )
            else:
                print(f"pytorch_injector (external) failed for {model_id}.")
                external_path = None

            injection_results.append(
                {
                    "model_id": model_id,
                    **payload_info,
                    "inject_success_bypass": inject_success_bypass,
                    "inject_success_baseline": inject_success_cycled,
                    "inject_success_pypi": inject_success_pypi,
                    "inject_success_external": inject_success_external,
                    "load_success": load_success,
                }
            )

            # Original
            print(
                f"Uploading Original {model_path} to {gcs_bucket_name} at {base_blob_path}/pytorcH_model.bin"
            )
            upload_to_gcs(
                model_path,
                gcs_bucket_name,
                f"{base_blob_path}/pytorch_model.bin",
            )

            # 2. Weights-bypass
            print(
                f"Uploading Weights {weights_bypass_path} to {gcs_bucket_name} at {weights_bypass_blob}"
            )
            if weights_bypass_path and weights_bypass_blob:
                upload_to_gcs(weights_bypass_path, gcs_bucket_name, weights_bypass_blob)

            # Fickling injected
            print(
                f"Uploading Weights {injected_model_path} to {gcs_bucket_name} at {base_blob_path}/pytorch_model_injected.bin"
            )
            if inject_success_cycled and injected_model_path:
                upload_to_gcs(
                    injected_model_path,
                    gcs_bucket_name,
                    f"{base_blob_path}/pytorch_model_injected.bin",
                )

            # PyPI injected
            print(f"Uploading Weights {pypi_path} to {gcs_bucket_name} at {pypi_blob}")
            if pypi_path:
                upload_to_gcs(pypi_path, gcs_bucket_name, pypi_blob)

            # External injected
            print(
                f"Uploading Weights {external_path} to {gcs_bucket_name} at {external_blob}"
            )
            if external_path and external_blob:
                upload_to_gcs(external_path, gcs_bucket_name, external_blob)

        except Exception as e:
            print(f"Injection/upload error for {model_id}: {e}")

        finally:
            for path in [
                weights_bypass_path,
                injected_model_path,
                pypi_path,
                external_path,
            ]:
                if path:
                    try:
                        os.remove(path)
                    except FileNotFoundError:
                        pass
            shutil.rmtree(local_dir, ignore_errors=True)
            print(f"Cleaned up local dir: {local_dir}")

        downloaded_models.append(model_id)

        log_filename = (
            f"wild_{TAG}_downloaded_models.csv"
            if direction == "asc"
            else f"{TAG}_downloaded_models.csv"
        )
        save_model_metadata(
            [download_log_df],
            [os.path.join(os.path.dirname(download_dir), log_filename)],
        )

    total_cycles = total_injections // len(final_list) if final_list else 0
    remaining = total_injections % len(final_list) if final_list else 0
    print(f"\nSummary:")
    print(f"  Models processed:          {len(downloaded_models)}")
    print(f"  Total cycled injections:   {total_injections}")
    print(f"  Complete payload cycles:   {total_cycles}")
    print(f"  Current cycle position:    {remaining}/{len(final_list)}")

    return downloaded_models, injection_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Download models or datasets from Hugging Face Hub."
    )
    parser.add_argument(
        "--type",
        choices=["model", "dataset"],
        required=True,
        help="Specify what to download: 'model' or 'dataset'",
    )
    parser.add_argument(
        "--base-dir", required=True, help="The place to download the files into"
    )
    parser.add_argument(
        "--tag",
        default=TAG,
        help="Tag to filter models or datasets (default: 'text-generation-inference')",
    )
    parser.add_argument(
        "--size",
        action="store_true",
        help="Tag to find how much space LIMIT_MATCHES models or datasets would take if downloaded",
    )
    parser.add_argument(
        "--upload", action="store_true", help="to upload, or not to uplaod"
    )
    parser.add_argument(
        "--list-path",
        help="point to pickle with model names to download/check",
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="scan without injecting and upload to gcs for flagged models",
    )
    parser.add_argument(
        "--mode",
        help="Mode for running the script until first half or second half or the whole list of repositories from HF for a particular cluster.",
    )
    parser.add_argument(
        "--all", action="store_true", help="Do all the injections and upload to gcs"
    )
    parser.add_argument(
        "--payload-dir", help="point to the directory to use for payloads"
    )
    parser.add_argument("--pyvenv", help="point to the virtual environment to use")
    parser.add_argument("--bucket-name", help="bucket name for gcs")
    args = parser.parse_args()
    models = []

    if args.tag:
        TAG = args.tag
    if args.list_path:
        models = []
        with open(args.list_path, "rb") as file:
            models = pickle.load(file)

        print("Loaded models:", models[:10])
    DOWNLOAD_DIR = args.base_dir
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    if args.size:
        get_download_size(args.type)
    elif args.type == "model":
        download_log_path = os.path.join(DOWNLOAD_DIR, f"{TAG}_downloaded_models.csv")

        if os.path.exists(download_log_path):
            # download_log_df = pd.read_csv("./feature-extraction_downloaded_models.csv")
            download_log_df = pd.read_csv(download_log_path)
            explored_models = set(download_log_df["name"].tolist())
        else:
            download_log_df = pd.DataFrame(
                columns=[
                    "name",
                    "likes",
                    "downloads",
                    "timestamp",
                    "repository",
                    "date_posted",
                    "last_commit",
                    "file_hash",
                    "file_name",
                    "file_size_bytes",
                    "number_of_detctions",
                    "detection_threshold_met",
                    "protectAiScan",
                    "avScan",
                    "pickleImportScan",
                    "jFrogScan",
                    "virusTotalScan",
                ]
            )
            explored_models = set()
        if args.scan_only:
            print("reaching here")
            downloaded_models = download_and_scan(
                download_dir=DOWNLOAD_DIR,
                space_limit_bytes=SPACE_LIMIT_BYTES,
                TAG=TAG,
                explored_models=explored_models,
                download_log_df=download_log_df,
                limit=LIMIT_MATCHES,
                direction="desc",
                models_to_download=models,
                mode=args.mode,
                pyvenv=args.pyvenv,
            )
        elif args.upload:
            print("reaching here")
            if args.bucket_name:
                BUCKET_NAME = args.bucket_name
                if args.all:
                    downloaded_models, injected_models = (
                        download_hf_inject_all_and_upload(
                            download_dir=DOWNLOAD_DIR,
                            space_limit_bytes=SPACE_LIMIT_BYTES,
                            TAG=TAG,
                            explored_models=explored_models,
                            download_log_df=download_log_df,
                            limit=LIMIT_MATCHES,
                            direction="desc",
                            gcs_bucket_name=BUCKET_NAME,
                            models_to_download=models,
                            payload_dir=args.payload_dir,
                        )
                    )
                else:
                    downloaded_models, injected_models = download_and_upload_injected(
                        download_dir=DOWNLOAD_DIR,
                        space_limit_bytes=SPACE_LIMIT_BYTES,
                        TAG=TAG,
                        explored_models=explored_models,
                        download_log_df=download_log_df,
                        limit=LIMIT_MATCHES,
                        direction="desc",
                        gcs_bucket_name=BUCKET_NAME,
                        models_to_download=models,
                    )
            else:
                print("Please provide bucket name for gcp uploading")
                exit()

        else:
            downloaded_models, injected_models = (
                download_models_with_immediate_injection(
                    download_dir=DOWNLOAD_DIR,
                    space_limit_bytes=SPACE_LIMIT_BYTES,
                    TAG=TAG,
                    explored_models=explored_models,
                    download_log_df=download_log_df,
                    limit=LIMIT_MATCHES,
                    direction="desc",  # or "asc" for wild run
                )
            )
        print(f"\nDownloaded {len(downloaded_models)} models.")
        download_log_df.to_csv(download_log_path, index=False)

    elif args.type == "dataset":
        download_datasets()
    else:
        print("Invalid type specified. Use 'model' or 'dataset'.")
