import os
import argparse
import csv

import traceback
from fickling.pytorch import PyTorchModelWrapper
from fickling.fickle import Pickled
from fickling.analysis import check_safety
import zipfile

SUPPORTED_EXTENSIONS = (
    ".bin",
    ".pkl",
    ".pickle",
    ".ckpt",
    ".pt",
    ".pth",
    ".th",
    ".joblib",
    ".dat",
    ".data",
)
# if not os.path.exists(log_file_path):
#    with open(log_file_path, mode="w", newline="", encoding="utf-8") as f:
#        writer = csv.writer(f)
#        writer.writerow(["file_path", "safety_result", "severity"])


def is_zip_model(path):
    try:
        with zipfile.ZipFile(path, "r") as zip_test:
            return True
    except zipfile.BadZipFile:
        return False


def analyze_pickle_safety(pickles, file_path):
    """Perform safety analysis on pickled data"""
    print(f"Performing safety analysis on: {file_path}")

    try:
        safety_result = check_safety(pickles)
        return safety_result
    #
    except Exception as e:
        print(f"Safety analysis failed: {e}")
        return None


def do_fickling_stuff(file_path):
    if is_zip_model(file_path):
        fickled_model = PyTorchModelWrapper(file_path, force=True)
        pickles = fickled_model.pickled
    else:
        with open(file_path, "rb") as f:
            pickles = Pickled.load(f)

    safety_result = analyze_pickle_safety(pickles, file_path)
    if safety_result is not None and hasattr(safety_result, "severity"):
        key = str(safety_result.severity)
    else:
        key = "UNKNOWN"
    safety_result_str = str(safety_result) if safety_result is not None else "None"

    try:
        severity_str = str(safety_result.severity)
    except Exception:
        severity_str = "N/A"
    # print("this is results", results)
    return severity_str, safety_result_str


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="fickling script to check for safety of files in a dirtectory"
    )
    parser.add_argument(
        "--base-dir", help="path to directory you want to check the files of"
    )
    args = parser.parse_args()
    log_file_path = os.path.join(args.base_dir, "fickle_safety_log.csv")
    sussy = []
    malicious_detected = []
    suspected_malicious = []
    basically_unsafe = []
    very_safe = []
    results = {}
    for path, folders, files in os.walk(args.base_dir):
        for filename in files:
            lower_filename = filename.lower()
            if lower_filename.endswith(SUPPORTED_EXTENSIONS):
                file_path = os.path.join(path, filename)
                print(f"\nProcessing: {file_path}")

                try:
                    severity_str, safety_result_str = do_fickling_stuff(file_path)
                    print("severitystr", severity_str)
                    print("safetyresult", safety_result_str)
                    input()

                    with open(
                        log_file_path, mode="a", newline="", encoding="utf-8"
                    ) as f:
                        writer = csv.writer(f)
                        writer.writerow([file_path, safety_result_str, severity_str])

                except Exception as e:
                    print(f"Failed to process '{file_path}': {type(e).__name__}: {e}")
                    traceback.print_exc()
                    print()
    print(results)
    print("Overtly Malicious", malicious_detected)
    print("Suspected malicious", suspected_malicious)
    print("liekly unsafe", basically_unsafe)
    print("safe", very_safe)
    print("sussy", sussy)
