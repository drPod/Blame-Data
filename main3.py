import os
import json
import logging
from typing import Dict, Any
from constants import (
    tokenization_loggingConfig,
    BENIGN_COMMITS_DIR,
    VULNERABILITY_INTRO_METADATA_DIR,
    TOKENIZED_BENIGN_COMMITS_DIR,
    TOKENIZED_VULN_INTRO_COMMITS_DIR,
)
from file_type_detector import determine_file_type
from tokenizer import tokenize_directory
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

    def process_filetypes(self, folder_path: str) -> Dict[str, Dict[str, str]]:
        self.logger.info(f"Processing filetypes in folder: {folder_path}")
        all_filetypes = {}

        try:
            for filename in os.listdir(folder_path):
                if filename.endswith(".json"):
                    json_path = os.path.join(folder_path, filename)
                    filetype = self.process_json_file(json_path)
                    all_filetypes[filename] = filetype
        except OSError as e:
            self.logger.error(f"Error accessing directory {folder_path}: {str(e)}")

        return all_filetypes

    def tokenize_commits(self, input_dir: str, output_dir: str, commit_type: str):
        self.logger.info(f"Tokenizing {commit_type} commits")
        try:
            tokenize_directory(input_dir, output_dir)
            self.logger.info(f"Successfully tokenized {commit_type} commits")
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
