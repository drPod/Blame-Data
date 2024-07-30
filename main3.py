import os
import json
import logging
from typing import Dict, Any
from tqdm import tqdm
from constants import (
    tokenization_loggingConfig,
    BENIGN_COMMITS_DIR,
    VULNERABILITY_INTRO_METADATA_DIR,
    TOKENIZED_BENIGN_COMMITS_DIR,
    TOKENIZED_VULN_INTRO_COMMITS_DIR,
)
from file_type_detector import determine_file_type
from tokenizer import tokenize_file
from ensure_directories import ensure_dirs


class CommitProcessor:
    def __init__(self):
        self.logger = self._setup_logger()
        ensure_dirs()

    def _setup_logger(self) -> logging.Logger:
        tokenization_loggingConfig()
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        return logger

    def process_json_file(self, json_file_path: str) -> Dict[str, str]:
        self.logger.info(f"Processing file: {json_file_path}")
        results = {}

        try:
            with open(json_file_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            self.logger.error(f"Error decoding JSON in file {json_file_path}: {str(e)}")
            return results
        except IOError as e:
            self.logger.error(f"IO error while reading file {json_file_path}: {str(e)}")
            return results

        file_changes = data.get("file_changes", {})

        for file_path, changes in file_changes.items():
            try:
                file_type = determine_file_type(file_path, changes)
                results[file_path] = file_type
                self.logger.info(f"File: {file_path}, Type: {file_type}")
            except Exception as e:
                self.logger.error(
                    f"Error determining file type for {file_path}: {str(e)}"
                )

        return results

    def tokenize_commits(self, input_dir: str, output_dir: str, commit_type: str):
        self.logger.info(f"Tokenizing {commit_type} commits")
        try:
            input_files = []
            for root, _, files in os.walk(input_dir):
                for file in files:
                    if file.endswith(".json"):
                        input_files.append(os.path.join(root, file))

            total_files = len(input_files)
            processed_files = 0

            with tqdm(
                total=total_files, desc=f"Tokenizing {commit_type} commits"
            ) as pbar:
                for input_path in input_files:
                    relative_path = os.path.relpath(input_path, input_dir)
                    output_path = os.path.join(output_dir, relative_path)

                    # Create output directory if it doesn't exist
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)

                    # Check if the output file already exists
                    if not os.path.exists(output_path):
                        tokenize_file(input_path, output_path)
                        processed_files += 1
                    else:
                        self.logger.info(
                            f"Skipping already processed file: {relative_path}"
                        )

                    pbar.update(1)

            self.logger.info(
                f"Successfully tokenized {processed_files} out of {total_files} {commit_type} commits"
            )
        except Exception as e:
            self.logger.error(f"Error tokenizing {commit_type} commits: {str(e)}")

    def run(self):
        self.logger.info("Starting commit processing")

        self.tokenize_commits(
            VULNERABILITY_INTRO_METADATA_DIR,
            TOKENIZED_VULN_INTRO_COMMITS_DIR,
            "vulnerability-introducing",
        )

        self.tokenize_commits(
            BENIGN_COMMITS_DIR, TOKENIZED_BENIGN_COMMITS_DIR, "benign"
        )

        self.logger.info("Commit processing completed")


def main():
    processor = CommitProcessor()
    processor.run()


if __name__ == "__main__":
    main()
