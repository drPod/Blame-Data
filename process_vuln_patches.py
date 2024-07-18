import os
import json
import logging
from git import Repo
from tqdm import tqdm

from constants import (
    VULNERABILITY_PATCHES_DIR,
    VULNERABILITY_INTRO_METADATA_DIR,
    loggingConfig,
)
from ensure_directories import ensure_dirs


def get_patch_info(patch_content):
    file_changes = {}
    current_file = None
    for line in patch_content.split("\n"):
        if line.startswith("diff --git"):
            current_file = line.split()[-1][2:]
            file_changes[current_file] = {"added_lines": [], "removed_lines": []}
        elif current_file:
            if line.startswith("+") and not line.startswith("+++"):
                file_changes[current_file]["added_lines"].append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                file_changes[current_file]["removed_lines"].append(line[1:])
    return file_changes


def process_vuln_patches():
    ensure_dirs()

    for cve_dir in tqdm(
        os.listdir(VULNERABILITY_PATCHES_DIR), desc="Processing vulnerability patches"
    ):
        patches_path = os.path.join(VULNERABILITY_PATCHES_DIR, cve_dir)
        if not os.path.isdir(patches_path):
            continue

        # Create CVE-specific directory in VULNERABILITY_INTRO_METADATA_DIR
        cve_output_dir = os.path.join(VULNERABILITY_INTRO_METADATA_DIR, cve_dir)
        os.makedirs(cve_output_dir, exist_ok=True)

        # Check if this CVE has already been processed
        processed_flag_file = os.path.join(cve_output_dir, "processed")
        if os.path.exists(processed_flag_file):
            logging.info(f"CVE {cve_dir} has already been processed. Skipping.")
            continue

        cve_processed = False

        for patch_file in os.listdir(patches_path):
            if not patch_file.endswith(".patch"):
                continue

            patch_path = os.path.join(patches_path, patch_file)
            output_path = os.path.join(cve_output_dir, f"{patch_file[:-6]}.json")

            if os.path.exists(output_path):
                logging.info(
                    f"Metadata for {cve_dir}, commit {patch_file[:-6]} already exists. Skipping."
                )
                cve_processed = True
                continue

            with open(patch_path, "r") as f:
                patch_content = f.read()

            patch_info = get_patch_info(patch_content)

            metadata = {
                "cve_id": cve_dir,
                "commit_id": patch_file[:-6],
                "file_changes": patch_info,
            }

            with open(output_path, "w") as f:
                json.dump(metadata, f, indent=2)

            logging.info(
                f"Processed and saved metadata for {cve_dir}, commit {patch_file[:-6]}"
            )
            cve_processed = True

        if cve_processed:
            # Create a flag file to indicate that this CVE has been processed
            with open(processed_flag_file, "w") as f:
                f.write("")

            patch_info = get_patch_info(patch_content)

            metadata = {
                "cve_id": cve_dir,
                "commit_id": patch_file[:-6],
                "file_changes": patch_info,
            }

            with open(output_path, "w") as f:
                json.dump(metadata, f, indent=2)

            logging.info(
                f"Processed and saved metadata for {cve_dir}, commit {patch_file[:-6]}"
            )
            cve_processed = True

        if cve_processed:
            # Create a flag file to indicate that this CVE has been processed
            with open(processed_flag_file, "w") as f:
                f.write("")


if __name__ == "__main__":
    loggingConfig()
    process_vuln_patches()
