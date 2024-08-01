import os
import json
import numpy as np
from typing import List, Dict
from tqdm import tqdm
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
    # Check if output file already exists and is up to date
    if os.path.exists(output_file) and os.path.getmtime(
        output_file
    ) >= os.path.getmtime(input_file):
        return  # Skip processing if output is up to date

    data = read_json_file(input_file)
    processed_data = {}

    for word, vector in list(data.items())[:threshold]:
        processed_data[word] = vector

    # Pad if necessary
    while len(processed_data) < threshold:
        processed_data[f"pad_{len(processed_data)}"] = pad_vector

    write_json_file(output_file, processed_data)


def process_folder(
    input_folder: str, output_folder: str, threshold: int, pad_vector: List[float]
):
    os.makedirs(output_folder, exist_ok=True)
    files_to_process = []

    for root, _, files in os.walk(input_folder):
        for filename in files:
            if filename.endswith(".json"):
                input_file = os.path.join(root, filename)
                relative_path = os.path.relpath(root, input_folder)
                output_subdir = os.path.join(output_folder, relative_path)
                os.makedirs(output_subdir, exist_ok=True)
                output_file = os.path.join(output_subdir, filename)
                files_to_process.append((input_file, output_file))

    for input_file, output_file in tqdm(
        files_to_process, desc=f"Processing {input_folder}"
    ):
        process_json_file(input_file, output_file, threshold, pad_vector)


def get_vector_dim(directory: str) -> int:
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".json"):
                file_path = os.path.join(root, filename)
                data = read_json_file(file_path)
                if data:
                    return len(next(iter(data.values())))
    return 0


def delete_vectors_if_exceeds_threshold(
    file_path: str, threshold: int, pad_vector: List[float]
):
    data = read_json_file(file_path)
    if len(data) > threshold:
        processed_data = dict(list(data.items())[:threshold])
        write_json_file(file_path, processed_data)


def main():
    # Ensure directories exist
    ensure_dirs()

    # Set the fixed threshold
    THRESHOLD = 500

    # Get the vector dimension from existing files
    vector_dim = get_vector_dim(VECTOR_VULN_INTRO_COMMITS_DIR)
    if vector_dim == 0:
        vector_dim = get_vector_dim(VECTOR_BENIGN_COMMITS_DIR)

    # Set the pad vector
    pad_vector = [0.0] * vector_dim if vector_dim > 0 else []

    print(f"Using fixed threshold: {THRESHOLD}")
    print(f"Determined pad vector dimension: {len(pad_vector)}")

    # Delete vectors if they exceed the threshold
    for folder in [VECTOR_VULN_INTRO_COMMITS_DIR, VECTOR_BENIGN_COMMITS_DIR]:
        for root, _, files in os.walk(folder):
            for filename in tqdm(files, desc=f"Deleting excess vectors in {folder}"):
                if filename.endswith(".json"):
                    delete_vectors_if_exceeds_threshold(
                        os.path.join(root, filename), THRESHOLD, pad_vector
                    )

    process_folder(
        VECTOR_VULN_INTRO_COMMITS_DIR,
        PADDED_VULN_INTRO_COMMITS_DIR,
        THRESHOLD,
        pad_vector,
    )
    process_folder(
        VECTOR_BENIGN_COMMITS_DIR, PADDED_BENIGN_COMMITS_DIR, THRESHOLD, pad_vector
    )


if __name__ == "__main__":
    main()
