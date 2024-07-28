import re
import json
import os
import logging
from typing import Dict, List
from constants import tokenization_loggingConfig
from file_type_detector import determine_file_type


def tokenize_code(code: str, language: str) -> List[str]:
    # Basic tokenization
    tokens = re.findall(r"\w+|[^\w\s]", code)

    # Subtokenization
    subtokens = []
    for token in tokens:
        # Split camelCase and PascalCase
        subtokens.extend(
            re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\W|$)|\d+", token)
        )

    # Convert to lowercase for consistency
    return [subtoken.lower() for subtoken in subtokens]


def process_file_changes(
    file_changes: Dict[str, Dict[str, List[str]]]
) -> Dict[str, Dict[str, List[List[str]]]]:
    tokenized_changes = {}
    for file_path, changes in file_changes.items():
        file_type = determine_file_type(file_path, changes)
        language = file_type.split("/")[1] if "/" in file_type else file_type

        tokenized_changes[file_path] = {
            "added_lines": [
                tokenize_code(line, language) for line in changes["added_lines"]
            ],
            "removed_lines": [
                tokenize_code(line, language) for line in changes["removed_lines"]
            ],
        }
    return tokenized_changes


def tokenize_commit(commit_data: Dict) -> Dict:
    tokenized_commit = commit_data.copy()
    tokenized_commit["file_changes"] = process_file_changes(commit_data["file_changes"])
    return tokenized_commit


def tokenize_directory(input_dir: str, output_dir: str):
    tokenization_loggingConfig()

    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.endswith(".json"):
                input_path = os.path.join(root, file)
                relative_path = os.path.relpath(input_path, input_dir)
                output_path = os.path.join(output_dir, relative_path)

                os.makedirs(os.path.dirname(output_path), exist_ok=True)

                with open(input_path, "r") as f:
                    commit_data = json.load(f)

                tokenized_data = tokenize_commit(commit_data)

                with open(output_path, "w") as f:
                    json.dump(tokenized_data, f, indent=2)

                logging.info(f"Tokenized and saved: {output_path}")
