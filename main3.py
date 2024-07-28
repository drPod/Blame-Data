import os
import json
import logging
from constants import tokenization_loggingConfig
from file_type_detector import determine_file_type
from tokenizer import tokenize_directory
from constants import (
    BENIGN_COMMITS_DIR,
    VULNERABILITY_INTRO_METADATA_DIR,
    TOKENIZED_BENIGN_COMMITS_DIR,
    TOKENIZED_VULN_INTRO_COMMITS_DIR,
)


def process_json_file(json_file_path):
    with open(json_file_path, "r") as f:
        data = json.load(f)

    file_changes = data.get("file_changes", {})
    results = {}

    for file_path in file_changes.keys():
        file_type = determine_file_type(file_path, file_changes[file_path])
        results[file_path] = file_type
        logging.info(f"File: {file_path}, Type: {file_type}")

    return results


def process_filetypes(folder_path):
    tokenization_loggingConfig()
    all_filetypes = {}

    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            json_path = os.path.join(folder_path, filename)
            logging.info(f"Processing file: {json_path}")
            filetype = process_json_file(json_path)
            all_filetypes[filename] = filetype

    return all_filetypes


def main():
    tokenization_loggingConfig()

    logging.info("PROCESSING VULNERABILITY INTRODUCING COMMITS")
    tokenize_directory(
        VULNERABILITY_INTRO_METADATA_DIR, TOKENIZED_VULN_INTRO_COMMITS_DIR
    )

    logging.info("PROCESSING BENIGN COMMITS")
    tokenize_directory(BENIGN_COMMITS_DIR, TOKENIZED_BENIGN_COMMITS_DIR)


if __name__ == "__main__":
    main()
