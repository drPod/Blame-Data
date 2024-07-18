import os
import json
import logging
from tqdm import tqdm

from constants import (
    COMMIT_METADATA_DIR,
    VULNERABILITY_INTRO_METADATA_DIR,
    loggingConfig,
)


def check_duplicates():
    logging.info("Checking for duplicates...")

    security_patch_commits = set()
    vuln_intro_commits = set()

    # Collect security patch commits
    for file in tqdm(
        os.listdir(COMMIT_METADATA_DIR), desc="Processing security patch metadata"
    ):
        if file.endswith(".json"):
            with open(os.path.join(COMMIT_METADATA_DIR, file), "r") as f:
                data = json.load(f)
                security_patch_commits.add(data["commit_id"])

    # Collect vulnerability-introducing commits
    for file in tqdm(
        os.listdir(VULNERABILITY_INTRO_METADATA_DIR),
        desc="Processing vuln intro metadata",
    ):
        if file.endswith(".json"):
            vuln_intro_commits.add(
                file.split("_")[-1][:-5]
            )  # Extract commit ID from filename

    # Check for duplicates
    duplicates = security_patch_commits.intersection(vuln_intro_commits)

    if duplicates:
        logging.warning(f"Found {len(duplicates)} duplicate commits:")
        for commit in duplicates:
            logging.warning(f"Duplicate commit: {commit}")
    else:
        logging.info("No duplicates found.")


if __name__ == "__main__":
    loggingConfig()
    check_duplicates()
