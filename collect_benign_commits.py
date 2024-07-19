import os
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

    logging.info(f"Starting to process CVEs from {VULNERABILITY_INTRO_METADATA_DIR}")
    for cve_dir in tqdm(
        os.listdir(VULNERABILITY_INTRO_METADATA_DIR), desc="Processing CVEs"
    ):
        cve_path = os.path.join(VULNERABILITY_INTRO_METADATA_DIR, cve_dir)
        if not os.path.isdir(cve_path):
            logging.debug(f"Skipping non-directory: {cve_path}")
            continue

        logging.info(f"Processing CVE directory: {cve_dir}")
        for vuln_file in os.listdir(cve_path):
            if not vuln_file.endswith(".json"):
                logging.debug(f"Skipping non-JSON file: {vuln_file}")
                continue

            logging.info(f"Processing vulnerability file: {vuln_file}")
            with open(os.path.join(cve_path, vuln_file), "r") as f:
                vuln_data = json.load(f)

            commit_id = vuln_data.get("commit_id")
            if not commit_id:
                logging.warning(f"No commit_id found in {vuln_file}. Skipping.")
                continue

            repo_url, project_name = get_repo_info(commit_id)
            if not repo_url or not project_name:
                logging.warning(f"No repo found for commit {commit_id}. Skipping.")
                continue

            repo_path = os.path.join(REPO_CACHE_DIR, project_name)
            if not os.path.exists(repo_path):
                logging.warning(
                    f"Repository not found in cache for {project_name}. Skipping."
                )
                continue

            logging.info(f"Processing repo: {project_name}")
            repo = Repo(repo_path)
            exclude_commits = [commit_id]

            for i in range(BENIGN_COMMITS_PER_VULN):
                benign_commit = get_random_commit(repo, exclude_commits)
                if not benign_commit:
                    logging.info(f"No more valid commits for {project_name}. Skipping.")
                    break

                output_file = os.path.join(
                    BENIGN_COMMITS_DIR, f"{project_name}_{benign_commit.hexsha}.json"
                )
                patch_file = os.path.join(
                    BENIGN_PATCHES_DIR, f"{project_name}_{benign_commit.hexsha}.patch"
                )

                if os.path.exists(output_file) and os.path.exists(patch_file):
                    logging.info(
                        f"Benign commit {benign_commit.hexsha} for {project_name} already processed. Skipping."
                    )
                    exclude_commits.append(benign_commit.hexsha)
                    continue

                commit_url = f"{repo_url}/commit/{benign_commit.hexsha}"
                patch_content = get_patch_content(commit_url)

                if patch_content:
                    with open(patch_file, "w") as f:
                        f.write(patch_content)

                    patch_info = get_patch_info(patch_content)

                    benign_data = {
                        "cve_id": "BENIGN",
                        "project_name": project_name,
                        "commit_id": benign_commit.hexsha,
                        "file_changes": patch_info,
                    }

                    with open(output_file, "w") as f:
                        json.dump(benign_data, f, indent=2)

                    logging.info(
                        f"Processed benign commit {benign_commit.hexsha} for {project_name}"
                    )
                else:
                    logging.warning(
                        f"Failed to get patch for commit {benign_commit.hexsha} of {project_name}"
                    )

                exclude_commits.append(benign_commit.hexsha)


if __name__ == "__main__":
    loggingConfig()
    collect_benign_commits()
