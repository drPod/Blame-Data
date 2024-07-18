import os
import json
import logging
from git import Repo
from tqdm import tqdm
import requests
import csv
import re

from constants import (
    COMMIT_METADATA_DIR,
    VULNERABILITY_PATCHES_DIR,
    PATCH_CACHE_DIR,
    loggingConfig,
)
from ensure_directories import ensure_dirs
from get_cache import get_or_create_repo

CSV_FILE = "commits_with_parent_ids.csv"


def get_repo_url(commit_id):
    with open(CSV_FILE, "r") as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            if row[4] == commit_id:  # Commit ID is in the 5th column
                return row[5]  # Repo URL is in the 6th column
    return None


def get_removed_lines(patch_content):
    removed_lines = []
    for line in patch_content.split("\n"):
        if line.startswith("-") and not line.startswith("---"):
            removed_lines.append(line[1:].strip())
    return removed_lines


def blame_removed_lines(repo, file_path, removed_lines, security_patch_commit):
    try:
        # Get the parent commit of the security patch
        parent_commit = repo.commit(security_patch_commit + "^")

        # Blame on the parent commit
        blame = repo.blame(parent_commit, file_path)
        vuln_introducing_commits = set()
        for line in removed_lines:
            for commit, lines in blame:
                if line in [l.strip() for l in lines]:
                    # Only add commit if it's an ancestor of the security patch
                    if repo.is_ancestor(commit.hexsha, security_patch_commit):
                        vuln_introducing_commits.add(commit.hexsha)

        # Remove the security patch commit itself, if present
        vuln_introducing_commits.discard(security_patch_commit)

        return list(vuln_introducing_commits)
    except Exception as e:
        logging.error(f"Error in blame_removed_lines for {file_path}: {str(e)}")
        return []


def get_patch_content(commit_url):
    try:
        patch_url = commit_url.split("#")[0] + ".patch"
        response = requests.get(patch_url)
        response.raise_for_status()
        return response.text
    except Exception as e:
        logging.error(f"Error fetching patch from {patch_url}: {str(e)}")
        return None


def analyze_vulnerabilities():
    ensure_dirs()

    for cve_file in tqdm(
        os.listdir(COMMIT_METADATA_DIR), desc="Analyzing vulnerabilities"
    ):
        if not cve_file.endswith(".json"):
            continue

        cve_id = cve_file[:-5]  # Remove .json extension
        cve_output_dir = os.path.join(VULNERABILITY_PATCHES_DIR, cve_id)
        os.makedirs(cve_output_dir, exist_ok=True)

        input_path = os.path.join(COMMIT_METADATA_DIR, cve_file)

        with open(input_path, "r") as f:
            security_patch_data = json.load(f)

        commit_id = security_patch_data["commit_id"]
        repo_url = get_repo_url(commit_id)

        if not repo_url:
            logging.warning(
                f"No repo_url found for {cve_id}, commit {commit_id}. Skipping."
            )
            continue

        repo = get_or_create_repo(repo_url)
        if repo is None:
            logging.error(f"Failed to get or create repo for {repo_url}. Skipping.")
            continue

        # Get the patch file from patch_cache
        patch_file = os.path.join(PATCH_CACHE_DIR, f"{commit_id}.patch")
        if not os.path.exists(patch_file):
            logging.warning(
                f"No patch file found for {cve_id}, commit {commit_id}. Skipping."
            )
            continue

        with open(patch_file, "r") as f:
            patch_content = f.read()

        # Extract file paths and removed lines from the patch
        file_patches = re.split(r"diff --git ", patch_content)[
            1:
        ]  # Split patch into per-file sections
        for file_patch in file_patches:
            file_path = file_patch.split(" b/")[1].split("\n")[0]
            removed_lines = get_removed_lines(file_patch)

            vuln_commits = blame_removed_lines(
                repo, file_path, removed_lines, commit_id
            )

            for vuln_commit in vuln_commits:
                commit_url = f"{repo_url}/commit/{vuln_commit}"
                output_file = os.path.join(cve_output_dir, f"{vuln_commit}.patch")

                if os.path.exists(output_file):
                    logging.info(
                        f"Patch for CVE {cve_id}, commit {vuln_commit} already exists. Skipping."
                    )
                    continue

                vuln_patch_content = get_patch_content(commit_url)

                if vuln_patch_content:
                    with open(output_file, "w") as f:
                        f.write(vuln_patch_content)
                    logging.info(f"Saved patch for CVE {cve_id}, commit {vuln_commit}")


if __name__ == "__main__":
    loggingConfig()
    analyze_vulnerabilities()
