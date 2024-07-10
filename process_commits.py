from tqdm import tqdm
import csv
import os
import json
import logging

from ensure_directories import ensure_dirs
from constants import COMMIT_METADATA_DIR
from constants import loggingConfig
from read_existing_data import read_existing_blame_data, read_existing_metadata
from get_cache import get_or_create_repo, get_patch_info, get_commit_metadata


def process_commits(input_file, blame_output_file):
    loggingConfig()
    ensure_dirs()
    repos = {}

    existing_blame_data = read_existing_blame_data(blame_output_file)

    with open(input_file, "r") as in_f, open(
        blame_output_file, "a", newline=""
    ) as blame_out_f:
        reader = csv.DictReader(in_f)
        blame_fieldnames = reader.fieldnames + ["malicious_files", "used_context_lines"]
        blame_writer = csv.DictWriter(blame_out_f, fieldnames=blame_fieldnames)

        if not existing_blame_data:
            blame_writer.writeheader()

        total_rows = sum(1 for row in reader)
        in_f.seek(0)
        next(reader)  # Skip header row

        current_cve = None
        for row in tqdm(reader, desc="Processing commits", total=total_rows):
            cve_id = row["cve_id"]
            commit_id = row["commit_id"]

            # Log when starting a new CVE
            if cve_id != current_cve:
                if current_cve is not None:
                    logging.info(f"Finished processing CVE: {current_cve}")
                current_cve = cve_id
                logging.info(f"Starting to process CVE: {cve_id}")

            # Check if we need to process this commit
            existing_row = existing_blame_data.get(commit_id)
            existing_metadata = read_existing_metadata(cve_id)

            if (
                existing_row
                and existing_metadata
                and all(field in existing_row for field in blame_fieldnames)
                and "commit_metadata" in existing_metadata
            ):
                logging.info(
                    f"Skipping commit: {commit_id} because it's already been processed"
                )
                continue  # Skip if we have complete data for this commit
            if existing_row:
                logging.info(f"Reprocessing commit: {commit_id}")

            project_name = row["project_name"]
            repo_url = row["repo_url"]
            commit_url = row["commit_url"]

            if repo_url not in repos:
                repo = get_or_create_repo(repo_url)
                if repo is None:
                    continue
                repos[repo_url] = repo
            else:
                repo = repos[repo_url]

            patch_info = get_patch_info(commit_url)
            logging.info(f"Patch info: {patch_info}")
            if not patch_info:
                logging.warning(f"No patch info found for commit: {commit_id}")
                continue

            malicious_files = list(patch_info.keys())
            used_context_lines = any(
                file_info["used_context_lines"] for file_info in patch_info.values()
            )

            commit_data = {
                "cve_id": cve_id,
                "project_name": project_name,
                "commit_id": commit_id,
                "malicious_files": malicious_files,
                "file_changes": {},
            }

            for filename, file_info in patch_info.items():
                commit_data["file_changes"][filename] = {
                    "malicious_lines": file_info["malicious_lines"],
                    "used_context_lines": file_info["used_context_lines"],
                }

            row["malicious_files"] = ",".join(malicious_files)
            row["used_context_lines"] = "Yes" if used_context_lines else "No"
            blame_writer.writerow(row)

            # Get metadata for the commit
            metadata = get_commit_metadata(repo, commit_id)
            if metadata:
                commit_data["commit_metadata"] = metadata

            # Write individual JSON file for each CVE
            json_filename = os.path.join(COMMIT_METADATA_DIR, f"{cve_id}.json")
            with open(json_filename, "w") as json_out_f:
                json.dump(commit_data, json_out_f, indent=2)

    logging.info(
        f"Processing complete. Results saved to {blame_output_file} and {COMMIT_METADATA_DIR}"
    )
