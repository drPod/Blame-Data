import os
import json
from typing import List, Dict
from collections import Counter
from constants import (
    TOKENIZED_BENIGN_COMMITS_DIR,
    TOKENIZED_VULN_INTRO_COMMITS_DIR,
    PADDED_VULN_INTRO_COMMITS_DIR,
    PADDED_BENIGN_COMMITS_DIR,
)


def read_json_file(file_path: str) -> Dict:
    with open(file_path, "r") as f:
        return json.load(f)


def write_json_file(file_path: str, data: Dict):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)


def process_lines(
    lines: List[List[str]], threshold: int, pad_token: str
) -> List[List[str]]:
    if len(lines) > threshold:
        return lines[:threshold]
    else:
        return lines + [[pad_token]] * (threshold - len(lines))


def process_file_changes(file_changes: Dict, threshold: int, pad_token: str) -> Dict:
    processed_changes = {}
    for file_name, changes in file_changes.items():
        processed_changes[file_name] = {
            "added_lines": process_lines(changes["added_lines"], threshold, pad_token),
            "removed_lines": process_lines(
                changes["removed_lines"], threshold, pad_token
            ),
        }
    return processed_changes


def process_json_file(
    input_file: str, output_file: str, threshold: int, pad_token: str
):
    data = read_json_file(input_file)
    data["file_changes"] = process_file_changes(
        data["file_changes"], threshold, pad_token
    )
    write_json_file(output_file, data)


def process_folder(
    input_folder: str, output_folder: str, threshold: int, pad_token: str
):
    os.makedirs(output_folder, exist_ok=True)
    for filename in os.listdir(input_folder):
        if filename.endswith(".json"):
            input_file = os.path.join(input_folder, filename)
            output_file = os.path.join(output_folder, filename)
            process_json_file(input_file, output_file, threshold, pad_token)


def determine_threshold_and_pad_token(vuln_folder: str, benign_folder: str) -> tuple:
    max_lines = 0
    all_tokens = []

    def process_file(file_path):
        nonlocal max_lines
        data = read_json_file(file_path)
        for changes in data["file_changes"].values():
            max_lines = max(
                max_lines, len(changes["added_lines"]), len(changes["removed_lines"])
            )
            for lines in changes["added_lines"] + changes["removed_lines"]:
                all_tokens.extend(lines)

    for folder in [vuln_folder, benign_folder]:
        for filename in os.listdir(folder):
            if filename.endswith(".json"):
                process_file(os.path.join(folder, filename))

    # Set threshold to the maximum number of lines found
    threshold = max_lines

    # Determine pad token (choose a token that doesn't appear in the dataset)
    token_counter = Counter(all_tokens)
    pad_token = "<PAD>"
    while pad_token in token_counter:
        pad_token += "_"

    return threshold, pad_token


def delete_tokens_if_exceeds_threshold(file_path: str, threshold: int, pad_token: str):
    data = read_json_file(file_path)
    for file_name, changes in data["file_changes"].items():
        for change_type in ["added_lines", "removed_lines"]:
            for i, lines in enumerate(changes[change_type]):
                if len(lines) > threshold:
                    data["file_changes"][file_name][change_type][i] = [pad_token]
    write_json_file(file_path, data)


def main():
    threshold, pad_token = determine_threshold_and_pad_token(
        TOKENIZED_VULN_INTRO_COMMITS_DIR, TOKENIZED_BENIGN_COMMITS_DIR
    )

    print(f"Determined threshold: {threshold}")
    print(f"Determined pad token: {pad_token}")

    # Delete tokens if they exceed the threshold
    for folder in [TOKENIZED_VULN_INTRO_COMMITS_DIR, TOKENIZED_BENIGN_COMMITS_DIR]:
        for filename in os.listdir(folder):
            if filename.endswith(".json"):
                delete_tokens_if_exceeds_threshold(
                    os.path.join(folder, filename), threshold, pad_token
                )

    process_folder(
        TOKENIZED_VULN_INTRO_COMMITS_DIR,
        PADDED_VULN_INTRO_COMMITS_DIR,
        threshold,
        pad_token,
    )
    process_folder(
        TOKENIZED_BENIGN_COMMITS_DIR, PADDED_BENIGN_COMMITS_DIR, threshold, pad_token
    )


if __name__ == "__main__":
    main()
