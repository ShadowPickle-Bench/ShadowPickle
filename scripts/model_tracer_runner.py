"""
ModelTracer Dynamic analysis module for model file security analysis.
Combines tracing and parsing functionality into callable functions.
Taken from https://github.com/s2e-lab/hf-model-analyzer/tree/main/scripts
"""

import sys
import opcode
import inspect
import torch

# import tensorflow as tf
import numpy as np

# import dill
# import onnx
# import joblib
import pickle
import csv
import pandas as pd
import os
import logging
import subprocess
from typing import Tuple, List, Optional

TIMEOUT = 120
logger = logging.getLogger(__name__)

commands_of_interest = ["execve", "connect", "socket", "chmod"]
searching = ["exec(", "eval(", "connect(", "socket("]


def is_callback_invocation(function_code, offset):
    opcode_name = opcode.opname[function_code.co_code[offset]]
    return "CALL" in opcode_name and "PRECALL" not in opcode_name


def trace_with_csv(writer):
    def analyze(frame, event, arg):
        frame.f_trace_opcodes = True
        function_code = frame.f_code
        offset = frame.f_lasti
        function_name = function_code.co_name

        if not is_callback_invocation(function_code, offset):
            return analyze

        lineno = frame.f_lineno
        source_lines, start = inspect.getsourcelines(function_code)
        actual_line = source_lines[lineno - start]
        variable_values = [f"{name}={frame.f_locals[name]}" for name in frame.f_locals]

        writer.writerow(
            [event, function_name, lineno, actual_line.strip(), variable_values]
        )
        return analyze

    return analyze


def run_strace(filepath: str, strace_command: List[str], outfile: str) -> bool:
    """Run strace on the model file loading process."""
    try:
        modified_strace_command = [
            "timeout",
            "--preserve-status",
            "--signal=TERM",
            f"{TIMEOUT}s",
        ] + strace_command
        print("Modified strace command", modified_strace_command)
        # a = ["timeout", "--preserve-status", "--signal=TERM", f"{TIMEOUT}s"] + strace_command
        # print(" ".join(a))
        # print(" ".join(strace_command))
        # modified_strace_command =  strace_command
        result = subprocess.run(
            modified_strace_command, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        print("returncode:", result.returncode)
        print("stderr:", result.stderr.decode())
        print("stdout:", result.stdout.decode())
        if result.returncode != 0:
            logger.debug(
                f"Failed to run strace for {filepath}: {result.stderr.decode('utf-8')}"
            )
            return False
    except subprocess.TimeoutExpired:
        logger.warning("ModelTracer strace has hit the timeout limit.")
    except Exception as e:
        logger.error(f"ModelTracer strace has led to an error: {e}")
        return False

    return True


def run_strace2csv(input_file: str, output_file: str) -> bool:
    """Convert strace output to CSV format."""
    command = ["strace2csv", input_file, "--out", output_file]
    result = subprocess.run(command, stderr=subprocess.PIPE)

    if result.returncode != 0:
        logger.debug(f"Failed to run strace2csv for {input_file}: {result.stderr}")
        return False
    return True


def trace_model_loading(
    filepath: str, method: str, results_dir: str = "./results_model_tracer"
) -> Tuple[str, str, str]:
    os.makedirs(results_dir, exist_ok=True)

    repo, file = filepath.rsplit("/", 1) if "/" in filepath else (".", filepath)
    base_name = repo.replace("/", "_") + "_" + file

    tracer_csv = os.path.join(results_dir, f"{base_name}_tracer.csv")
    strace_output = os.path.join(results_dir, f"{base_name}_strace_output.txt")
    strace_csv = os.path.join(results_dir, f"{base_name}_strace.csv")

    strace_command = [
        "strace",
        "-f",
        "-tt",
        "-T",
        "-y",
        "-yy",
        "-s",
        "2048",
        "-o",
        strace_output,
    ]

    method_configs = {
        "tensorflow": (
            lambda: tf.keras.models.load_model(filepath),
            f'import tensorflow; tensorflow.keras.models.load_model("{filepath}")',
        ),
        "numpy": (lambda: np.load(filepath), f'import numpy; numpy.load("{filepath}")'),
        "onnx": (lambda: onnx.load(filepath), f'import onnx; onnx.load("{filepath}")'),
        "TorchScript": (
            lambda: torch.jit.load(filepath),
            f'import torch; torch.jit.load("{filepath}")',
        ),
        "joblib": (
            lambda: joblib.load(filepath),
            f'import joblib; joblib.load("{filepath}")',
        ),
        "dill": (
            lambda: dill.load(open(filepath, "rb")),
            f'import dill; dill.load(open("{filepath}", "rb"))',
        ),
        "pickle": (
            lambda: pickle.load(open(filepath, "rb")),
            f'import pickle; f = open("{filepath}", "rb"); pickle.load(f); f.close()',
        ),
        "torch": (
            lambda: torch.load(
                filepath, weights_only=False, map_location=torch.device("cpu")
            ),
            f'import torch; torch.load("{filepath}", weights_only=False, map_location=torch.device("cpu"))',
        ),
    }

    if method not in method_configs:
        raise ValueError(
            f"Unknown method: {method}. Must be one of {list(method_configs.keys())}"
        )

    load_func, string_loader = method_configs[method]

    with open(tracer_csv, "w") as output_csv:
        writer = csv.writer(output_csv)
        writer.writerow(["event", "function_name", "line_number", "line", "variables"])

        try:
            sys.settrace(trace_with_csv(writer))
            load_func()
            sys.settrace(None)
        except Exception as e:
            logger.debug(f"Python tracer failed for {filepath}: {e}")
            sys.settrace(None)

    extra_path = "payloads/obfuscated"
    strace_command.extend(
        [
            "python",
            "-c",
            f'import sys; sys.path.append("{extra_path}"); {string_loader}',
        ]
    )
    run_strace(filepath, strace_command, strace_output)

    if os.path.exists(strace_output):
        run_strace2csv(strace_output, strace_csv)

    return tracer_csv, strace_output, strace_csv


def analyze_strace_csv(strace_csv_path: str) -> bool:
    if not os.path.exists(strace_csv_path):
        logger.warning(f"Strace CSV not found: {strace_csv_path}")
        return False

    try:
        df = pd.read_csv(strace_csv_path)

        execve_indices = df[df["syscall"] == "execve"].index
        if len(execve_indices) > 0:
            df = df.drop(execve_indices[0])

        filtered = df[df["syscall"].isin(commands_of_interest)]

        if not filtered.empty:
            malicious_dir = os.path.join(
                os.path.dirname(strace_csv_path), "malicious_dynamic"
            )
            os.makedirs(malicious_dir, exist_ok=True)

            base_name = os.path.basename(strace_csv_path).replace("_strace.csv", "")
            malicious_filepath = os.path.join(
                malicious_dir, f"{base_name}_malicious_results.csv"
            )
            filtered.to_csv(malicious_filepath)
            return True

        return False

    except Exception as e:
        logger.error(f"Error analyzing strace CSV {strace_csv_path}: {e}")
        return False


def analyze_strace_text(strace_output_path: str) -> bool:
    if not os.path.exists(strace_output_path):
        logger.warning(f"Strace output not found: {strace_output_path}")
        return False

    malicious_commands = []

    try:
        with open(strace_output_path, "r") as f:
            for line in f:
                if any(s in line for s in searching):
                    malicious_commands.append(line)

        if malicious_commands:
            # Save to malicious directory
            malicious_dir = os.path.join(
                os.path.dirname(strace_output_path), "malicious_dynamic"
            )
            os.makedirs(malicious_dir, exist_ok=True)

            base_name = os.path.basename(strace_output_path).replace(
                "_strace_output.txt", ""
            )
            malicious_filepath = os.path.join(
                malicious_dir, f"{base_name}_malicious_strace.txt"
            )

            with open(malicious_filepath, "w") as f:
                for line in malicious_commands:
                    f.write(f"{line}\n")
                    f.write("\n")
            return True

        return False

    except Exception as e:
        logger.error(f"Error analyzing strace text {strace_output_path}: {e}")
        return False


def cleanup_temp_files(strace_output: str, strace_csv: str) -> None:
    """
    Delete temporary strace files.
    """
    for filepath in [strace_output, strace_csv]:
        if os.path.exists(filepath):
            try:
                # print("does this delete this?:", filepath)
                os.remove(filepath)
                logger.debug(f"Deleted temporary file: {filepath}")
            except Exception as e:
                logger.warning(f"Failed to delete {filepath}: {e}")


def model_tracer_check(
    filepath: str, method: str, results_dir: str = "./model_tracer_results"
) -> bool:
    try:
        tracer_csv, strace_output, strace_csv = trace_model_loading(
            filepath, method, results_dir
        )

        found_unsafe_csv = analyze_strace_csv(strace_csv)
        found_unsafe_text = analyze_strace_text(strace_output)

        is_malicious = found_unsafe_csv or found_unsafe_text

        cleanup_temp_files(strace_output, strace_csv)
        logger.debug(f"Cleaned up temporary files for benign model: {filepath}")

        # Return True if analysis found something suspicious lol
        return is_malicious

    except Exception as e:
        logger.error(f"Dynamic analysis failed for {filepath}: {e}")
        return False


if __name__ == "__main__":
    print(model_tracer_check("pytorch_model_edited_injector_obfuscated.bin", "torch"))
