import subprocess


def run(command):
    result = subprocess.call(command, shell=True)
    return result
