import os
import json
import csv
from constants import COMMIT_METADATA_DIR


def read_existing_blame_data(blame_output_file):
    existing_data = {}
    if os.path.exists(blame_output_file):
        with open(blame_output_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_data[row["commit_id"]] = row
    return existing_data


def read_existing_metadata(cve_id):
    json_filename = os.path.join(COMMIT_METADATA_DIR, f"{cve_id}.json")
    if os.path.exists(json_filename):
        with open(json_filename, "r") as f:
            return json.load(f)
    return None
