from tqdm import tqdm
import csv
import os
import json
import subprocess
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
        blame_fieldnames = reader.fieldnames + [
            "malicious_files",
            "malicious_commit_hashes",
            "used_context_lines",
        ]
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
            if not patch_info:
                logging.warning(f"No patch info found for commit: {commit_id}")
                continue

            malicious_commit_hashes = set()
            malicious_files = set()
            used_context_lines = False
            commit_data = {
                "cve_id": cve_id,
                "project_name": project_name,
                "commit_id": commit_id,
                "malicious_files": [],
            }

            logging.info(f"Processing commit: {commit_id}")
            for filename, changes in patch_info.items():
                removed_lines = changes["removed"]
                context_lines = changes["context"]
                lines_to_check = removed_lines if removed_lines else context_lines

                if not lines_to_check:
                    continue

                try:
                    logging.info(f"Running git blame on file: {filename}")
                    blame_process = subprocess.Popen(
                        [
                            "git",
                            "blame",
                            "-l",
                            "-C",
                            "-M",
                            commit_id,
                            "--",
                            filename,
                        ],
                        cwd=repo.working_dir,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )

                    blame_output, blame_error = blame_process.communicate()

                    if blame_process.returncode != 0:
                        logging.warning(
                            f"Git blame failed for file {filename}: {blame_error.decode('utf-8', errors='replace')}"
                        )
                        continue

                    # Try to decode with UTF-8 first, fall back to latin-1 if that fails
                    try:
                        blame_output = blame_output.decode("utf-8")
                    except UnicodeDecodeError:
                        logging.warning(
                            f"Failed to decode blame output as UTF-8 for file {filename}, falling back to latin-1"
                        )
                        blame_output = blame_output.decode("latin-1")

                except Exception as e:
                    logging.warning(
                        f"Could not run git blame on file: {filename}. Error: {str(e)}. Skipping file."
                    )
                    continue

                logging.info(f"Checking file: {filename}")

                file_is_malicious = False  # Flag to check if file is malicious
                malicious_lines = []  # List to store malicious lines
                for line in blame_output.split(
                    "\n"
                ):  # Iterate over each line in the blame output
                    if not line:
                        continue  # Skip empty lines
                    parts = line.split(")")
                    if len(parts) < 2:
                        continue  # Skip lines that don't have a commit hash and line content
                    hash_and_line = parts[0]
                    commit_hash = hash_and_line.split(" ")[0]
                    line_content = ")".join(parts[1:]).strip()

                    if line_content in lines_to_check or any(
                        check_line in line_content for check_line in lines_to_check
                    ):
                        if commit_hash.startswith(
                            "^"
                        ):  # Remove ^ from the beginning of the commit hash
                            commit_hash = commit_hash[1:]
                        malicious_commit_hashes.add(commit_hash)
                        file_is_malicious = True
                        malicious_lines.append(line_content)

                if file_is_malicious:
                    malicious_files.add(filename)
                    commit_data["malicious_files"].append(
                        {"filename": filename, "malicious_lines": malicious_lines}
                    )

            if not removed_lines and context_lines:
                used_context_lines = True

            row["malicious_files"] = ",".join(malicious_files)
            row["malicious_commit_hashes"] = ",".join(malicious_commit_hashes)
            row["used_context_lines"] = "Yes" if used_context_lines else "No"
            blame_writer.writerow(row)

            # Get metadata for malicious commits
            for hash in malicious_commit_hashes:
                metadata = get_commit_metadata(repo, hash)
                if metadata:
                    metadata["original_hash"] = hash
                    commit_data["commit_metadata"] = metadata

            # Write individual JSON file for each CVE
            json_filename = os.path.join(COMMIT_METADATA_DIR, f"{cve_id}.json")
            with open(json_filename, "w") as json_out_f:
                json.dump(commit_data, json_out_f, indent=2)

    logging.info(
        f"Processing complete. Results saved to {blame_output_file} and {COMMIT_METADATA_DIR}"
    )
