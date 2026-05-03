# Create or use provided work directory
import argparse
import io
import os
from pathlib import Path
import pickle
import sys
import traceback
from utils import list_files_gcs, download_from_gcs
import inspect

# INFO: Make sure that these are the patched versions of the programs.
import torch as torch_patched
from fickling.pytorch import PyTorchModelWrapper
from fickling.analysis import check_safety
import pandas as pd

print(sys.modules["torch"])
print(sys.modules["fickling"])
file_path = inspect.getfile(torch_patched.load)
print(f"Function file path: {file_path}")

CSV_COLUMNS = [
    "name",
    "fickling_result",
    "fickling_category",
    "weights_only_result",
    "fickling_output",
    "weights_only_output",
]

PYTORCH_FILES = {
    "obfuscated": "_obfuscated.bin",
    "benign": "pytorch_model.bin",
    "overwritten": "_weights_bypass.bin",
    "pypi": "pytorch_model_injected_pypi.bin",
}


def init_csv():
    """Create the CSV file with headers if it doesn't already exist."""
    if not os.path.exists(CSV_PATH):
        pd.DataFrame(columns=CSV_COLUMNS).to_csv(CSV_PATH, index=False)


def append_row(row: dict):
    """Append a single result row to the CSV log."""
    df = pd.DataFrame([row], columns=CSV_COLUMNS)
    df.to_csv(CSV_PATH, mode="a", header=False, index=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bucket-name", help="bucket to query")
    parser.add_argument("--prefix", help="prefix to check")
    parser.add_argument(
        "--mode",
        help="Name of the dataset being used. E.g. overwritten, benign, pypi, etc.",
        choices=["benign", "overwritten", "obfuscated", "pypi"],
    )
    args = parser.parse_args()
    print(
        f"Listing files in bucket '{args.bucket_name}' with args.prefix '{args.prefix}'..."
    )

    CSV_PATH = f"patched_scan_results_{args.mode}.csv"
    download_dir = "download"
    log_dir = f"logs/{args.mode}"
    os.makedirs(download_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    init_csv()

    models = list_files_gcs(args.bucket_name, args.prefix)[1:]
    file_to_consider = PYTORCH_FILES[args.mode]
    if args.mode in ["overwritten", "obfuscated"]:
        all_models = [i for i in models if i.endswith(file_to_consider)]
    else:
        all_models = [
            i
            for i in models
            if ("feature_extraction" not in i and file_to_consider in i)
        ]
    print("=" * 60)
    print(all_models[:10])
    print(f"Collected {len(all_models)} models from GCS.")
    print("=" * 60)

    for gcs_model_path in all_models:
        model_id = os.path.basename(os.path.dirname(gcs_model_path))
        local_dir = os.path.join(download_dir, "pytorch_model.bin")
        print(model_id)

        isDownloaded = download_from_gcs(args.bucket_name, gcs_model_path, local_dir)
        if not isDownloaded:
            print("Error: Problem with downloading")
            exit()
        print(f"Done downloading model: {gcs_model_path}")

        print("Scanning with Pytorch weights_only!")
        weight_only_result = False
        weights_only_output_buf = io.StringIO()
        old_stdout = sys.stdout

        try:
            sys.stdout = weights_only_output_buf
            with open(local_dir, "rb") as f:
                torch_patched.load(
                    f, weights_only=True, map_location=torch_patched.device("cpu")
                )
            sys.stdout = old_stdout

            print("Weights only successfully loaded. It didn't detect it :)")
            weight_only_result = False
            weights_only_output_buf.write("Loaded successfully – no threat detected.\n")

        except pickle.UnpicklingError as e:
            sys.stdout = old_stdout
            print("Weights only detected it :(")
            weight_only_result = True
            weights_only_output_buf.write(f"UnpicklingError: {e}\n")

        except Exception:
            sys.stdout = old_stdout
            print("Weights only has this to say:")
            tb = traceback.format_exc()
            print(tb)
            weight_only_result = False
            weights_only_output_buf.write(tb)

        weights_only_output_str = weights_only_output_buf.getvalue().strip()
        print(f"Done scanning with weights_only for {gcs_model_path}")

        print("Scanning with fickling!")
        fickling_result_str = "None"
        fickling_category = "N/A"
        fickling_output_buf = io.StringIO()

        try:
            pickles = PyTorchModelWrapper(Path(local_dir), force=True).pickled
            json_out = os.path.join(log_dir, f"fickling_output_{model_id}.json")
            safety_result = check_safety(pickles, json_output_path=json_out)

            fickling_severity_cause = (
                str(safety_result) if safety_result is not None else "None"
            )
            try:
                fickling_severity = str(safety_result.severity)
            except Exception:
                fickling_severity = "N/A"

            print("fickling_severity", fickling_severity)
            fickling_output_buf.write(fickling_result_str)
            print(f"Fickling is obtaining this result: {safety_result}")
            print(
                f"This is the severity level {fickling_category} and the "
                f"safety result from fickling: {fickling_result_str}"
            )

        except Exception:
            tb = traceback.format_exc()
            print("Error: Some error occurred when unpickling:")
            print(tb)
            fickling_output_buf.write(tb)
            fickling_severity = 0
            fickling_severity_cause = "UNKNOWN"

        fickling_output_str = fickling_output_buf.getvalue().strip()
        print(f"Done scanning with fickling for {gcs_model_path}")

        row = {
            "name": model_id,
            "fickling_result": bool(fickling_severity),
            "fickling_category": str(fickling_severity),
            "weights_only_result": weight_only_result,
            "fickling_output": str(fickling_severity_cause),
            "weights_only_output": weights_only_output_str,
        }
        append_row(row)
        print(f"Logged result for {model_id} to {CSV_PATH}")

        os.remove(local_dir)

    print("Done scanning and collecting output!")
    print(f"Results saved to: {CSV_PATH}")
