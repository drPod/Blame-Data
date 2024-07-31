import os
import json
import numpy as np
from typing import List, Dict
from constants import (
    VECTOR_VULN_INTRO_COMMITS_DIR,
    VECTOR_BENIGN_COMMITS_DIR,
    PADDED_VULN_INTRO_COMMITS_DIR,
    PADDED_BENIGN_COMMITS_DIR,
)
from ensure_directories import ensure_dirs


def read_json_file(file_path: str) -> Dict:
    with open(file_path, "r") as f:
        return json.load(f)


def write_json_file(file_path: str, data: Dict):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)


def process_vectors(
    vectors: List[List[float]], threshold: int, pad_vector: List[float]
) -> List[List[float]]:
    if len(vectors) > threshold:
        return vectors[:threshold]
    else:
        return vectors + [pad_vector] * (threshold - len(vectors))


def process_file_changes(
    file_changes: Dict, threshold: int, pad_vector: List[float]
) -> Dict:
    processed_changes = {}
    for file_name, changes in file_changes.items():
        processed_changes[file_name] = {
            "added_lines": process_vectors(
                changes["added_lines"], threshold, pad_vector
            ),
            "removed_lines": process_vectors(
                changes["removed_lines"], threshold, pad_vector
            ),
        }
    return processed_changes


def process_json_file(
    input_file: str, output_file: str, threshold: int, pad_vector: List[float]
):
    data = read_json_file(input_file)
    data["file_changes"] = process_file_changes(
        data["file_changes"], threshold, pad_vector
    )
    write_json_file(output_file, data)


def process_folder(
    input_folder: str, output_folder: str, threshold: int, pad_vector: List[float]
):
    os.makedirs(output_folder, exist_ok=True)
    for filename in os.listdir(input_folder):
        if filename.endswith(".json"):
            input_file = os.path.join(input_folder, filename)
            output_file = os.path.join(output_folder, filename)
            process_json_file(input_file, output_file, threshold, pad_vector)


def determine_threshold_and_pad_vector(vuln_folder: str, benign_folder: str) -> tuple:
    max_lines = 0
    vector_dim = None

    def process_file(file_path):
        nonlocal max_lines, vector_dim
        data = read_json_file(file_path)
        for changes in data["file_changes"].values():
            max_lines = max(
                max_lines, len(changes["added_lines"]), len(changes["removed_lines"])
            )
            if vector_dim is None and changes["added_lines"]:
                vector_dim = len(changes["added_lines"][0])

    for folder in [vuln_folder, benign_folder]:
        for filename in os.listdir(folder):
            if filename.endswith(".json"):
                process_file(os.path.join(folder, filename))

    threshold = max_lines
    pad_vector = [0.0] * vector_dim if vector_dim is not None else []

    return threshold, pad_vector


def delete_vectors_if_exceeds_threshold(
    file_path: str, threshold: int, pad_vector: List[float]
):
    data = read_json_file(file_path)
    for file_name, changes in data["file_changes"].items():
        for change_type in ["added_lines", "removed_lines"]:
            if len(changes[change_type]) > threshold:
                data["file_changes"][file_name][change_type] = changes[change_type][
                    :threshold
                ]
    write_json_file(file_path, data)


def main():

    ensure_dirs()

    threshold, pad_vector = determine_threshold_and_pad_vector(
        VECTOR_VULN_INTRO_COMMITS_DIR, VECTOR_BENIGN_COMMITS_DIR
    )

    print(f"Determined threshold: {threshold}")
    print(f"Determined pad vector dimension: {len(pad_vector)}")

    # Delete vectors if they exceed the threshold
    for folder in [VECTOR_VULN_INTRO_COMMITS_DIR, VECTOR_BENIGN_COMMITS_DIR]:
        for filename in os.listdir(folder):
            if filename.endswith(".json"):
                delete_vectors_if_exceeds_threshold(
                    os.path.join(folder, filename), threshold, pad_vector
                )

    process_folder(
        VECTOR_VULN_INTRO_COMMITS_DIR,
        PADDED_VULN_INTRO_COMMITS_DIR,
        threshold,
        pad_vector,
    )
    process_folder(
        VECTOR_BENIGN_COMMITS_DIR, PADDED_BENIGN_COMMITS_DIR, threshold, pad_vector
    )


if __name__ == "__main__":
    main()
