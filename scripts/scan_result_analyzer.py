import sys
import pprint
import matplotlib.pyplot as plt
import os
import argparse
import csv
import pandas as pd
import re
from collections import defaultdict
from matplotlib.patches import Patch
from torch._weights_only_unpickler import _get_allowed_globals

csv.field_size_limit(sys.maxsize)
WEIGHTS_ONLY_WHITELIST = _get_allowed_globals().keys()


def picklescan_check(row, picklescan_trues, picklescan_legit, picklescan_libraries):
    raw_name = row.get("name", "").strip()
    picklescan_result = row.get("picklescan_result", "").strip()
    picklescan_output = row.get("picklescan_output", "").strip()
    # print(picklescan_result)
    # print(raw_name)
    if picklescan_result == "True":
        # print(picklescan_result)
        picklescan_trues.append(raw_name)
        # print(picklescan_output)
        if "Infected files" in picklescan_output:
            print("FOUND ONEEEEE PXIKLESCANNNN")
            print(raw_name)
            picklescan_legit.append(raw_name)
            pattern = r"dangerous import\s+'([^']+)'\s+FOUND"
            found_library = re.findall(pattern, picklescan_output)
            print("FOUNFUONFONFOUFNOFUFN", found_library)
            try:
                picklescan_libraries[found_library[0]] += 1
            except KeyError as e:
                picklescan_libraries[found_library[0]] = 1

    return picklescan_trues, picklescan_legit


def modelscan_check(row, modelscan_trues, modelscan_legit, modelscan_libraries):
    raw_name = row.get("name", "").strip()
    modelscan_result = row.get("modelscan_result", "").strip()
    modelscan_output = row.get("modelscan_output", "").strip()
    if modelscan_result == "True":
        modelscan_trues.append(raw_name)
        if "--- Summary ---" in modelscan_output:
            modelscan_legit.append(raw_name)
            # print("MODELSCANNNN FOUNDOUDUONDOUNDOUNDOUNDOUND", raw_name)
            pattern = r"unsafe operator\s+'([^']+)'\s+from module\s+'([^']+)'"
            matches = re.findall(pattern, modelscan_output)

            found_library = [f"{module} {operator}" for operator, module in matches]
            # print("ASDASDASDSADASDADASDS", found_library)
            try:
                modelscan_libraries[found_library[0]] += 1
            except KeyError as e:
                modelscan_libraries[found_library[0]] = 1
    return modelscan_trues, modelscan_legit


def weights_only_check(row, weights_only_trues):
    raw_name = row.get("name", "").strip()
    weights_only_result = row.get("weights_only_result", "").strip()
    if weights_only_result == "True":
        weights_only_trues.append(raw_name)
        # print("weights only sussy ahhhhhhh", raw_name)

    return weights_only_trues


def model_tracer_check(row, model_tracer_trues):
    raw_name = row.get("name", "").strip()
    if raw_name.split("/")[-1].endswith(".py"):
        return model_tracer_trues
    modeltracer_result = row.get("modeltracer_result", "").strip()
    if modeltracer_result == "True":
        model_tracer_trues.append(raw_name)
        # print("ALERT ALERT, MODELTRACER AHHHHHHH", raw_name)
    return model_tracer_trues


def fickling_check(row, fickling_trues, fickling_severities):
    raw_name = row.get("name", "").strip()
    fickling_result = row.get("fickling_result", "").strip()
    fickling_category = row.get("fickling_category", "").strip()
    try:
        fickling_severities[fickling_category] += 1
    except:
        fickling_severities[fickling_category] = 1
    if fickling_result == "True":
        fickling_trues.append(raw_name)
        # print("ALERT ALERT, FICKLING  AHHHHHHH", raw_name)
    # else:
    #     print("FICKLING DIDNT DETECT WHATHATHTAH", raw_name)
    return fickling_trues, fickling_severities


def count_trues(row, five_scanners, four_scanners, three_scanners, two_scanners):
    raw_name = row.get("name", "").strip()

    scanner_results = {
        "fickling": row.get("fickling_result", "").strip(),
        "modeltracer": row.get("modeltracer_result", "").strip(),
        "weights_only": row.get("weights_only_result", "").strip(),
        "modelscan": row.get("modelscan_result", "").strip(),
        "picklescan": row.get("picklescan_result", "").strip(),
    }

    detected_by = [
        scanner for scanner, result in scanner_results.items() if result == "True"
    ]

    no_of_trues = len(detected_by)

    if no_of_trues >= 2:
        entry = {
            "name": raw_name,
            "detected_by": detected_by,
        }
        if scanner_results["picklescan"] == "True":
            picklescan_output = row.get("picklescan_output", "").strip()

            if "Infected files" in picklescan_output:
                pattern = r"dangerous import\s+'([^']+)'\s+FOUND"
                found_libraries = re.findall(pattern, picklescan_output)

                if found_libraries:
                    entry["picklescan_libraries"] = found_libraries

        if scanner_results["modelscan"] == "True":
            modelscan_output = row.get("modelscan_output", "").strip()

            pattern = r"unsafe operator\s+'([^']+)'\s+from module\s+'([^']+)'"
            found_libraries = re.findall(pattern, modelscan_output)

            if found_libraries:
                entry["modelscan_libraries"] = found_libraries
        match no_of_trues:
            case 2:
                two_scanners.append(entry)
            case 3:
                three_scanners.append(entry)
            case 4:
                four_scanners.append(entry)
            case 5:
                five_scanners.append(entry)

    return five_scanners, four_scanners, three_scanners, two_scanners
    pass


def write_scanner_results(csv_path, four_scanners, five_scanners, modelhub):
    high_confidence = four_scanners + five_scanners
    tag = csv_path.rsplit("_", 1)[-1].removesuffix(".csv")
    file_path = "four_and_five_scanners.csv"
    file_exists = os.path.exists(file_path) and os.path.getsize(file_path) > 0

    existing_names = set()
    if file_exists:
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            existing_names = {row["name"] for row in reader}
    with open(file_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "name",
                "modelhub",
                "tag",
                "detections",
                "detected_by",
                "picklescan_libraries",
                "modelscan_libraries",
            ],
        )

        if not file_exists:
            writer.writeheader()

        for entry in high_confidence:
            detected_list = entry.get("detected_by", [])
            name = entry.get("name", "")
            if name in existing_names:
                continue
            writer.writerow(
                {
                    "name": entry.get("name", ""),
                    "modelhub": modelhub,
                    "tag": tag,
                    "detections": len(detected_list),
                    "detected_by": ", ".join(entry.get("detected_by", [])),
                    "picklescan_libraries": ", ".join(
                        entry.get("picklescan_libraries", [])
                    ),
                    "modelscan_libraries": ", ".join(
                        f"{lib} ({mod})"
                        for lib, mod in entry.get("modelscan_libraries", [])
                    )
                    if entry.get("modelscan_libraries")
                    else "",
                }
            )
    pass


def run_scans(csv_path, write_scans=None, modelhub=None):
    with open(csv_path, mode="r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        total = 0
        picklescan_trues = []
        picklescan_legit = []
        modelscan_trues = []
        modelscan_legit = []
        weights_only_trues = []
        modeltracer_trues = []
        fickling_trues = []
        fickling_severities = {}
        picklescan_libraries = {}
        modelscan_libraries = {}
        five_scanners = []
        four_scanners = []
        three_scanners = []
        two_scanners = []
        counted_names = []
        for row in reader:
            row_name = row.get("name", "").strip()
            # if row_name not in counted_names:
            #     counted_names.append(row_name)
            # else:
            #     continue
            # match = next((key for key in model_file_dict if key in row_name), None)
            #
            # if match:
            #     value = model_file_dict[match]
            #     print(match, value)
            #     if (
            #         row_name.endswith(tuple(value))
            #         and "Pickleball_data" not in row_name
            #     ):
            #         print(row_name)
            # continue
            # if row_name.endswith("pytorch_model.bin"):
            # if row_name.startswith("__"):
            #     row_name = row_name.replace("__", "", 1)
            #     print(row_name)
            # if "no_cluster" in row_name:
            #     continue
            # if row_name in names:
            picklescan_trues, picklescan_legit = picklescan_check(
                row, picklescan_trues, picklescan_legit, picklescan_libraries
            )
            modelscan_trues, modelscan_legit = modelscan_check(
                row, modelscan_trues, modelscan_legit, modelscan_libraries
            )
            weights_only_trues = weights_only_check(row, weights_only_trues)
            modeltracer_trues = model_tracer_check(row, modeltracer_trues)
            fickling_trues, ficklingn_severities = fickling_check(
                row, fickling_trues, fickling_severities
            )
            five_scanners, four_scanners, three_scanners, two_scanners = count_trues(
                row,
                five_scanners,
                four_scanners,
                three_scanners,
                two_scanners,
            )
            total += 1
            # if total >= 3000:
            #     break
            # print(picklescan_trues)
        # pp = pprint.PrettyPrinter(indent=4, sort_dicts=False)
        #
        # print(f"\nTwo scanners ({len(two_scanners)})")
        # pp.pprint(two_scanners)
        #
        # print(f"\nThree scanners ({len(three_scanners)})")
        # pp.pprint(three_scanners)
        #
        # print(f"\nFour scanners ({len(four_scanners)})")
        # pp.pprint(four_scanners)
        #
        # print(f"\nFive scanners ({len(five_scanners)})")
        # pp.pprint(five_scanners)
        # filename = "weights_detected_to_not.csv"
        # with open(filename, mode="w", newline="") as file:
        #     writer = csv.writer(file)
        #
        #     # Write header
        #     writer.writerow(["name"])
        #
        #     # Write each item as a row
        #     for item in weights_only_trues:
        #         writer.writerow([item.split("bypass/")[1].split("/")[0]])

        # print(f"CSV file '{filename}' created successfully.")
        print("total pciklesacns", len(picklescan_trues))
        print("picklescan without errors:", len(picklescan_legit))
        print("totao modelscans", len(modelscan_trues))
        print("legit modelscans", len(modelscan_legit))
        print("total weights_only", len(weights_only_trues))
        print("total modeltracer", len(modeltracer_trues))
        print("total fickling", len(fickling_trues))
        print("fickling_categories", fickling_severities)
        print("total models scanned", total)
        print("pciklescan libraries", picklescan_libraries)
        print("modelscan libraries", modelscan_libraries)

    if write_scans:
        write_scanner_results(csv_path, four_scanners, five_scanners, modelhub)

    return (
        picklescan_legit,
        modelscan_legit,
        weights_only_trues,
        modeltracer_trues,
        fickling_trues,
        total,
    )


def analyse_fickling_data(csv_path):
    with open(csv_path, mode="r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        fickling_anomalies = {}
        for row in reader:
            name = row.get("name", "").strip()
            if name.startswith("__"):
                name = name.replace("__", "", 1)
                print("name replaced", name)
            if name.endswith("pytorch_model.bin"):
                raw_name = row.get("fickling_output", "").strip()
                pattern = re.compile(r"from\s+([\w\.]+)\s+import\s+(\w+)")

                for module, name in pattern.findall(raw_name):
                    key = f"{module}.{name}"
                    try:
                        fickling_anomalies[key] += 1
                    except KeyError:
                        fickling_anomalies[key] = 1

    print(fickling_anomalies)
    gto = 0
    for i in fickling_anomalies:
        if fickling_anomalies[i] > 1:
            gto += 1

    print("number of libraries with more than 1 instance:", gto)

    top_30 = sorted(fickling_anomalies.items(), key=lambda x: x[1], reverse=True)[:15]

    keys = [item[0] for item in top_30]
    values = [item[1] for item in top_30]
    colors = [
        "red" if any(h in key for h in WEIGHTS_ONLY_WHITELIST) else "steelblue"
        for key in keys
    ]
    legend_elements = [
        Patch(facecolor="crimson", label="Weights_only overlap"),
        # Patch(facecolor="orange", label="Warning"),
        Patch(facecolor="steelblue", label="Fickling Specific"),
    ]
    plt.figure(figsize=(12, 6))
    plt.bar(keys, values, color=colors)

    plt.xlabel("Library Names")
    plt.ylabel("No. of Occurrences")
    plt.title("Top 15 Library Occurrences")

    plt.yscale("log")
    plt.legend(handles=legend_elements)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig("fickling_vs_weights.png", dpi=300, bbox_inches="tight")
    plt.show()
    return


def analyse_weights_data(csv_path):
    with open(csv_path, mode="r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        weights_anomalies = {}
        for row in reader:
            raw_name = row.get("weights_only_output", "").strip()
            match = re.search(r"GLOBAL\s+([a-zA-Z0-9_\.]+)", raw_name)
            if match:
                result = match.group(1)
                try:
                    weights_anomalies[result] += 1
                except KeyError:
                    weights_anomalies[result] = 1

    print(weights_anomalies)
    gto = 0
    for i in weights_anomalies:
        if weights_anomalies[i] > 1:
            gto += 1

    print("number of libraries with more than 1 instance:", gto)

    top_30 = sorted(weights_anomalies.items(), key=lambda x: x[1], reverse=True)[:30]

    keys = [item[0] for item in top_30]
    values = [item[1] for item in top_30]

    plt.figure(figsize=(12, 6))
    plt.bar(keys, values)

    plt.xlabel("Keys")
    plt.ylabel("Frequency")
    plt.title("Top 30 Frequencies")

    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()

    return


def write_results(results, modelhub, output_path, tag):
    (
        picklescan_legit,
        modelscan_legit,
        weights_only_trues,
        modeltracer_trues,
        fickling_trues,
        total_scanned,
    ) = results

    row = {
        "modelhub": modelhub,
        "tag": tag,
        "picklescan_legit_count": len(picklescan_legit),
        "modelscan_legit_count": len(modelscan_legit),
        "weights_only_count": len(weights_only_trues),
        "modeltracer_count": len(modeltracer_trues),
        "fickling_count": len(fickling_trues),
        "total_scanned": total_scanned,
    }

    file_exists = os.path.isfile(output_path)

    with open(output_path, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)

    print(f"Results written to {output_path}")
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to analyse the generated data")

    parser.add_argument("--csv-path", help="path to csv to analyse")
    parser.add_argument("--modelhub", help="name of the modelhub being analysed")
    parser.add_argument(
        "--output-path",
        default="opensource_scanning_results.csv",
        help="csv to output the results into",
    )
    parser.add_argument(
        "--write", action="store_true", help="to write output to csv or not"
    )
    parser.add_argument(
        "--analyse-fickling",
        action="store_true",
        help="whether to analyse fickling stuff",
    )
    parser.add_argument(
        "--analyse-weights",
        action="store_true",
        help="whether to analyse weights only stuff",
    )
    parser.add_argument(
        "--write-scans", action="store_true", help="write scanner results to a csv"
    )
    args = parser.parse_args()

    if args.analyse_fickling:
        print("analyising ficklning")
        analyse_fickling_data(args.csv_path)
        exit()
    if args.analyse_weights:
        print("analyising ficklning")
        analyse_weights_data(args.csv_path)
        exit()
    res = run_scans(args.csv_path, args.write_scans, args.modelhub)
    if args.write:
        tag = args.csv_path.rsplit("_", 1)[-1].removesuffix(".csv")
        write_results(res, args.modelhub, args.output_path, tag)
