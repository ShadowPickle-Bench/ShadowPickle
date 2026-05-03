import subprocess
import argparse
import sys
import os
import csv
import torch
from pickle import UnpicklingError

from fickling_safety import do_fickling_stuff
from model_tracer_runner import model_tracer_check


def modelscan_check(file_path, python_env):
    venv_path = python_env
    cmd = f"source {venv_path} && modelscan -p {file_path}"
    # Run the script using the other environment's Python
    result = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)

    print("STDOUT:", result.stdout)
    print("ModelScan STDERR:", result.stderr)
    print("Return code:", result.returncode)

    if "No issues found! 🎉" in result.stdout:
        return False
    else:
        if "--- Summary ---" not in result.stdout:
            print("modelscan crashed, disregarding the result for this one")
            return False
        return result.stdout


def picklescan_check(file_path):
    cmd = f"picklescan -p {file_path}"
    # Run the script using the other environment's Python
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    print("STDOUT:", result.stdout)
    print("Picklescan STDERR:", result.stderr)
    print("Return code:", result.returncode)

    if "Infected files: 0" in result.stdout or result.stderr:
        return False
    else:
        if "Infected files:" not in result.stdout:
            print("picklescan crashed, disregarding the result for this one")
            return False
        return result.stdout


def do_weights_only_check(file_path):
    try:
        torch.load(file_path, weights_only=True, map_location="cpu")
        return False, "Loading Successful"
    except UnpicklingError as e:
        print("Loading failed lol", e)
        return True, e


def do_open_source_checks(
    file_path, csv_file="opensource_tools_results.csv", python_env=None
):
    detectors_flagged = 0
    print("are we evne here")
    modelscan_result = modelscan_check(file_path, python_env)
    print(modelscan_result)
    if modelscan_result:
        detectors_flagged += 1
        print("modelscan thinks its the big bad, logging")

    try:
        fickling_severity, fickling_severity_cause = do_fickling_stuff(file_path)
        if (
            str(fickling_severity) == "Severity.OVERTLY_MALICIOUS"
            or str(fickling_severity) == "Severity.LIKELY_UNSAFE"
            or str(fickling_severity) == "Severity.LIKELY_OVERTLY_MALICIOUS"
            or str(fickling_severity) == "Severity.SUSPICIOUS"
            or str(fickling_severity) == "Severity.POSSIBLY_UNSAFE"
        ):
            detectors_flagged += 1
            print("fickling thinks its the big bad, loggging")
        print("fickling_severity", fickling_severity)
    except Exception as e:
        print("issue in unpickling Fickling", e)
        fickling_severity = 0
        fickling_severity_cause = "N/A"

    try:
        picklescan_result = picklescan_check(file_path)
    except Exception as e:
        print("issue in unpickling picklescan", e)
        picklescan_result = False
    print(picklescan_result)
    if picklescan_result:
        detectors_flagged += 1
        print("picklescan thinks its the big bad, logging")

    try:
        dynamic_result = model_tracer_check(file_path, "torch")
        print("modeltracer result", dynamic_result)
    except Exception as e:
        print("issue in unpickling Modeltracer", e)
        dynamic_result = False

    try:
        weights_only_result, weights_only_output = do_weights_only_check(file_path)
        print("weights only gives:", weights_only_result)
    except Exception as e:
        print("issue in unpickling weights_only", e)
        weights_only_result = False
        weights_only_output = e

    file_exists = os.path.isfile(csv_file)

    headers = [
        "name",
        "picklescan_result",
        "modelscan_result",
        "fickling_result",
        "modeltracer_result",
        "fickling_category",
        "weights_only_result",
        "picklescan_output",
        "modelscan_output",
        "fickling_output",
        "weights_only_output",
    ]

    row = {
        "name": file_path,
        "picklescan_result": bool(picklescan_result),
        "modelscan_result": bool(modelscan_result),
        "fickling_result": False
        if str(fickling_severity) == "Severity.LIKELY_SAFE"
        else bool(fickling_severity),
        "modeltracer_result": dynamic_result,
        "weights_only_result": bool(weights_only_result),
        "fickling_category": str(fickling_severity),
        "picklescan_output": str(picklescan_result),
        "modelscan_output": str(modelscan_result),
        "fickling_output": str(fickling_severity_cause),
        "weights_only_output": str(weights_only_output),
    }

    # Append to CSV
    with open(csv_file, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)
    return detectors_flagged + weights_only_result + dynamic_result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script to scan models with open-source scanners"
    )

    parser.add_argument("--model-path", help="path to modelto analyse")
    parser.add_argument("--venv-path", help="path to the environment")
    args = parser.parse_args()
    do_open_source_checks(args.model_path, args.venv_path)
