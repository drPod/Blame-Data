import os
import json
import logging
from multiprocessing import Pool
from tqdm import tqdm
from constants import (
    tokenization_loggingConfig,
    BENIGN_COMMITS_DIR,
    VULNERABILITY_INTRO_METADATA_DIR,
    TOKENIZED_BENIGN_COMMITS_DIR,
    TOKENIZED_VULN_INTRO_COMMITS_DIR,
)

# Set up logging
tokenization_loggingConfig()
logger = logging.getLogger(__name__)


def tokenize_line(text):
    return text.split()


def process_file_changes(file_changes):
    processed_changes = {}
    for file_path, changes in file_changes.items():
        processed_changes[file_path] = {
            "added_lines": [
                tokenize_line(line) for line in changes.get("added_lines", [])
            ],
            "removed_lines": [
                tokenize_line(line) for line in changes.get("removed_lines", [])
            ],
        }
    return processed_changes


def process_commit(commit_data):
    processed_commit = commit_data.copy()
    processed_commit["file_changes"] = process_file_changes(commit_data["file_changes"])
    return processed_commit


def process_file(args):
    input_path, output_path = args

    # Check if the output file already exists and is newer than the input file
    if os.path.exists(output_path) and os.path.getmtime(output_path) > os.path.getmtime(
        input_path
    ):
        logger.info(f"Skipping already processed file: {input_path}")
        return

    logger.info(f"Processing file: {input_path}")
    try:
        with open(input_path, "r") as f:
            commit_data = json.load(f)

        processed_data = process_commit(commit_data)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(processed_data, f, indent=2)

        logger.info(f"Processed and saved: {output_path}")
    except Exception as e:
        logger.error(f"Error processing file {input_path}: {str(e)}")


def process_directory(input_dir, output_dir):
    tasks = []
    for root, _, files in os.walk(input_dir):
        for file in files:
            if file.endswith(".json"):
                input_path = os.path.join(root, file)
                relative_path = os.path.relpath(input_path, input_dir)
                output_path = os.path.join(output_dir, relative_path)
                tasks.append((input_path, output_path))
    return tasks


def main():
    benign_tasks = process_directory(BENIGN_COMMITS_DIR, TOKENIZED_BENIGN_COMMITS_DIR)
    vuln_tasks = process_directory(
        VULNERABILITY_INTRO_METADATA_DIR, TOKENIZED_VULN_INTRO_COMMITS_DIR
    )

    all_tasks = benign_tasks + vuln_tasks

    with Pool(2) as p:
        list(
            tqdm(
                p.imap(process_file, all_tasks),
                total=len(all_tasks),
                desc="Processing files",
            )
        )


if __name__ == "__main__":
    main()
