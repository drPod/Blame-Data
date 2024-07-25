import os
import sys
import json
import random
import logging
from git import Repo, GitCommandError
import csv
from tqdm import tqdm
import subprocess
import re

from constants import (
    VULNERABILITY_INTRO_METADATA_DIR,
    REPO_CACHE_DIR,
    loggingConfig,
    BENIGN_COMMITS_DIR,
    BENIGN_PATCHES_DIR,
)

# Constants
CSV_FILE = "commits_with_parent_ids.csv"
BENIGN_COMMITS_PER_VULN = 5


def get_repo_info(commit_id):
    logging.debug(f"Searching for commit ID: {commit_id}")
    with open(CSV_FILE, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["commit_id"] == commit_id:
                logging.debug(
                    f"Found repo info: {row['repo_url']}, {row['project_name']}"
                )
                return row["repo_url"], row["project_name"]
    logging.warning(f"No repo info found for commit ID: {commit_id}")
    return None, None


def get_random_commit(repo, exclude_commits):
    all_commits = list(repo.iter_commits())
    valid_commits = [c for c in all_commits if c.hexsha not in exclude_commits]
    return random.choice(valid_commits) if valid_commits else None


def get_patch_content(commit_url):
    patch_url = f"{commit_url}.patch"
    try:
        result = subprocess.run(
            ["wget", "-q", "-O", "-", patch_url], capture_output=True, text=True
        )
        if result.returncode == 0:
            return result.stdout
        else:
            logging.error(f"Failed to fetch patch from {patch_url}: {result.stderr}")
            return None
    except Exception as e:
        logging.error(f"Error fetching patch from {patch_url}: {str(e)}")
        return None


def get_patch_info(patch_content):
    file_changes = {}
    current_file = None
    for line in patch_content.split("\n"):
        if line.startswith("diff --git"):
            match = re.search(r"a/(.*) b/(.*)", line)
            if match:
                current_file = match.group(2)
                file_changes[current_file] = {"added_lines": [], "removed_lines": []}
        elif current_file:
            if line.startswith("+") and not line.startswith("+++"):
                file_changes[current_file]["added_lines"].append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                file_changes[current_file]["removed_lines"].append(line[1:])
    return file_changes


def collect_benign_commits():
    os.makedirs(BENIGN_COMMITS_DIR, exist_ok=True)
    os.makedirs(BENIGN_PATCHES_DIR, exist_ok=True)

    cve_dirs = [
        d
        for d in os.listdir(VULNERABILITY_INTRO_METADATA_DIR)
        if os.path.isdir(os.path.join(VULNERABILITY_INTRO_METADATA_DIR, d))
    ]
    total_cves = len(cve_dirs)

    print(
        f"Starting to process {total_cves} CVEs from {VULNERABILITY_INTRO_METADATA_DIR}"
    )

    for cve_index, cve_dir in enumerate(cve_dirs, 1):
        cve_path = os.path.join(VULNERABILITY_INTRO_METADATA_DIR, cve_dir)

        print(f"\nProcessing CVE directory: {cve_dir} ({cve_index}/{total_cves})")
        sys.stdout.flush()  # Ensure the print statement is displayed immediately

        # Create CVE-specific output directories
        cve_benign_commits_dir = os.path.join(BENIGN_COMMITS_DIR, cve_dir)
        cve_benign_patches_dir = os.path.join(BENIGN_PATCHES_DIR, cve_dir)
        os.makedirs(cve_benign_commits_dir, exist_ok=True)
        os.makedirs(cve_benign_patches_dir, exist_ok=True)

        vuln_files = [f for f in os.listdir(cve_path) if f.endswith(".json")]
        for vuln_index, vuln_file in enumerate(vuln_files, 1):
            print(
                f"  Processing vulnerability file: {vuln_file} ({vuln_index}/{len(vuln_files)})"
            )
            sys.stdout.flush()

            with open(os.path.join(cve_path, vuln_file), "r") as f:
                vuln_data = json.load(f)

            commit_id = vuln_data.get("commit_id")
            if not commit_id:
                print(f"    No commit_id found in {vuln_file}. Skipping.")
                continue

            repo_url, project_name = get_repo_info(commit_id)
            if not repo_url or not project_name:
                print(f"    No repo found for commit {commit_id}. Skipping.")
                continue

            repo_path = os.path.join(REPO_CACHE_DIR, project_name)
            if not os.path.exists(repo_path):
                print(
                    f"    Repository not found in cache for {project_name}. Skipping."
                )
                continue

            print(f"    Processing repo: {project_name}")
            sys.stdout.flush()

            repo = Repo(repo_path)
            exclude_commits = [commit_id]

            benign_commits_processed = 0
            for i in range(BENIGN_COMMITS_PER_VULN):
                benign_commit = get_random_commit(repo, exclude_commits)
                if not benign_commit:
                    print(f"      No more valid commits for {project_name}. Skipping.")
                    break

                output_file = os.path.join(
                    cve_benign_commits_dir,
                    f"{project_name}_{benign_commit.hexsha}.json",
                )
                patch_file = os.path.join(
                    cve_benign_patches_dir,
                    f"{project_name}_{benign_commit.hexsha}.patch",
                )

                if os.path.exists(output_file) and os.path.exists(patch_file):
                    print(
                        f"      Benign commit {benign_commit.hexsha} for {project_name} already processed. Skipping."
                    )
                    exclude_commits.append(benign_commit.hexsha)
                    benign_commits_processed += 1
                    continue

                commit_url = f"{repo_url}/commit/{benign_commit.hexsha}"
                patch_content = get_patch_content(commit_url)

                if patch_content:
                    with open(patch_file, "w") as f:
                        f.write(patch_content)

                    patch_info = get_patch_info(patch_content)

                    benign_data = {
                        "cve_id": cve_dir,
                        "project_name": project_name,
                        "commit_id": benign_commit.hexsha,
                        "file_changes": patch_info,
                    }

                    with open(output_file, "w") as f:
                        json.dump(benign_data, f, indent=2)

                    print(
                        f"      Processed benign commit {benign_commit.hexsha} for {project_name}"
                    )
                    benign_commits_processed += 1
                else:
                    print(
                        f"      Failed to get patch for commit {benign_commit.hexsha} of {project_name}"
                    )

                exclude_commits.append(benign_commit.hexsha)
                sys.stdout.flush()

            print(
                f"    Completed processing {benign_commits_processed} benign commits for {project_name}"
            )
            sys.stdout.flush()

        print(f"Completed processing CVE: {cve_dir}")
        sys.stdout.flush()

    print("\nFinished processing all CVEs.")


if __name__ == "__main__":
    loggingConfig()
    collect_benign_commits()
