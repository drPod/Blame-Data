import os
import json
import logging
from git import Repo, GitCommandError
from tqdm import tqdm
import requests
import csv
import re

from constants import (
    COMMIT_METADATA_DIR,
    VULNERABILITY_PATCHES_DIR,
    PATCH_CACHE_DIR,
    VULNERABILITY_INTRO_METADATA_DIR,
    loggingConfig,
)
from ensure_directories import ensure_dirs
from get_cache import get_or_create_repo

CSV_FILE = "commits_with_parent_ids.csv"
CVES_TO_PROCESS_FILE = "CVEs_to_process.txt"


def read_cves_to_process():
    with open(CVES_TO_PROCESS_FILE, "r") as f:
        cves = f.read().splitlines()
    # Remove the last line and any empty lines
    return [cve.strip() for cve in cves[:-1] if cve.strip()]


def get_repo_url(commit_id):
    with open(CSV_FILE, "r") as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            if row[4] == commit_id:  # Commit ID is in the 5th column
                return row[5]  # Repo URL is in the 6th column
    return None


def get_lines_to_blame(patch_content):
    lines_to_blame = []
    lines = patch_content.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("+") and not line.startswith("+++"):
            # Get context lines (up to 3 lines before and after)
            start = max(0, i - 3)
            end = min(len(lines), i + 4)
            context = [
                l.strip() for l in lines[start:end] if not l.startswith(("+", "-", "@"))
            ]
            lines_to_blame.extend(context)
    return list(set(lines_to_blame))  # Remove duplicates


def is_valid_commit(repo, commit_hash):
    try:
        repo.git.rev_parse("--verify", commit_hash)
        return True
    except GitCommandError:
        return False


def blame_lines(repo, file_path, lines_to_blame, security_patch_commit):
    clean_security_patch_commit = security_patch_commit.lstrip("^")
    try:
        # Get the parent commit of the security patch
        try:
            parent_commit = repo.commit(clean_security_patch_commit + "^")
        except GitCommandError:
            logging.error(f"No parent commit found for {clean_security_patch_commit}")
            return []

        # Validate parent_commit
        if not is_valid_commit(repo, parent_commit.hexsha):
            logging.error(f"Invalid parent commit: {parent_commit.hexsha}")
            return []

        # Blame on the parent commit
        try:
            blame = repo.git.blame(
                "-l", parent_commit.hexsha, "--", file_path
            ).splitlines()
        except GitCommandError as e:
            if "no such path" in str(e).lower():
                logging.warning(
                    f"File {file_path} not found in commit {parent_commit.hexsha}"
                )
            else:
                logging.error(f"Git error in blame for {file_path}: {str(e)}")
            return []

        vuln_introducing_commits = set()

        for line in lines_to_blame:
            for blame_line in blame:
                if line.strip() in blame_line:
                    commit_hash = blame_line.split()[0]
                    # Clean the commit hash by removing leading carets
                    clean_commit_hash = commit_hash.lstrip("^")
                    if is_valid_commit(repo, clean_commit_hash):
                        try:
                            if repo.is_ancestor(
                                clean_commit_hash, security_patch_commit
                            ):
                                vuln_introducing_commits.add(clean_commit_hash)
                        except GitCommandError as e:
                            logging.error(
                                f"Error checking ancestry for {clean_commit_hash}: {str(e)}"
                            )

        # Remove the security patch commit itself, if present
        vuln_introducing_commits.discard(security_patch_commit)

        return list(vuln_introducing_commits)
    except Exception as e:
        logging.error(f"Unexpected error in blame_lines for {file_path}: {str(e)}")
        return []


def find_commit_in_all_branches(repo, commit_hash):
    try:
        # First, try to find the commit directly
        commit = repo.commit(commit_hash)
        return commit
    except GitCommandError:
        # If not found, search in all branches
        for branch in repo.branches:
            try:
                repo.git.checkout(branch.name)
                commit = repo.commit(commit_hash)
                return commit
            except GitCommandError:
                continue
    return None


def get_patch_content(commit_url):
    try:
        patch_url = commit_url.split("#")[0] + ".patch"
        response = requests.get(patch_url)
        response.raise_for_status()
        return response.text
    except Exception as e:
        logging.error(f"Error fetching patch from {patch_url}: {str(e)}")
        return None


def fetch_and_save_patch(commit_id, repo_url):
    commit_url = f"{repo_url}/commit/{commit_id}"
    patch_content = get_patch_content(commit_url)
    if patch_content:
        patch_file = os.path.join(PATCH_CACHE_DIR, f"{commit_id}.patch")
        with open(patch_file, "w") as f:
            f.write(patch_content)
        logging.info(f"Fetched and saved patch for commit {commit_id}")
        return patch_file
    return None


def analyze_vulnerabilities():
    ensure_dirs()

    # Read CVEs to process once at the beginning
    cves_to_process = read_cves_to_process()
    logging.info(f"Found {len(cves_to_process)} CVEs to process")

    for cve_file in tqdm(cves_to_process, desc="Analyzing vulnerabilities"):
        if not cve_file.endswith(".json"):
            logging.warning(f"Skipping {cve_file} as it doesn't end with .json")
            continue

        cve_id = cve_file[:-5]  # Remove .json extension

        # Create CVE-specific directory in VULNERABILITY_INTRO_METADATA_DIR
        cve_output_dir = os.path.join(VULNERABILITY_INTRO_METADATA_DIR, cve_id)
        os.makedirs(cve_output_dir, exist_ok=True)

        # Check if this CVE has already been processed
        processed_flag_file = os.path.join(
            VULNERABILITY_INTRO_METADATA_DIR, f"{cve_id}_processed"
        )
        if os.path.exists(processed_flag_file):
            logging.info(f"CVE {cve_id} has already been processed. Skipping.")
            continue

        cve_output_dir = os.path.join(VULNERABILITY_PATCHES_DIR, cve_id)
        os.makedirs(cve_output_dir, exist_ok=True)

        input_path = os.path.join(COMMIT_METADATA_DIR, cve_file)

        if not os.path.exists(input_path):
            logging.error(f"File not found: {input_path}. Skipping.")
            continue

        try:
            with open(input_path, "r") as f:
                security_patch_data = json.load(f)
        except json.JSONDecodeError:
            logging.error(f"Failed to parse JSON for {cve_id}. Skipping.")
            continue

        commit_id = security_patch_data.get("commit_id")
        if not commit_id:
            logging.warning(f"No commit_id found for {cve_id}. Skipping.")
            continue

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

        # Reset and update the repo before processing each CVE
        try:
            repo.git.reset("--hard")
            repo.git.clean("-xdf")
            repo.git.fetch("--all")
            repo.remotes.origin.pull()
            logging.info(f"Repository reset and updated for {cve_id}")
        except GitCommandError as e:
            logging.error(f"Git error in repo reset for {repo_url}: {str(e)}")
            continue

        # Get the patch file from patch_cache or fetch it if missing
        patch_file = os.path.join(PATCH_CACHE_DIR, f"{commit_id}.patch")
        if not os.path.exists(patch_file):
            logging.info(
                f"Patch file not found for {cve_id}, commit {commit_id}. Attempting to fetch."
            )
            patch_file = fetch_and_save_patch(commit_id, repo_url)
            if not patch_file:
                logging.warning(
                    f"Failed to fetch patch for {cve_id}, commit {commit_id}. Skipping."
                )
                continue

        with open(patch_file, "r") as f:
            patch_content = f.read()

        # Extract file paths and lines to blame from the patch
        file_patches = re.split(r"diff --git ", patch_content)[
            1:
        ]  # Split patch into per-file sections
        cve_has_patches = False
        for file_patch in file_patches:
            match = re.search(r"a/(.*) b/(.*)", file_patch)
            if not match:
                logging.warning(
                    f"Could not extract file path from patch for {cve_id}. Skipping this file."
                )
                continue
            file_path = match.group(2)
            lines_to_blame = get_lines_to_blame(file_patch)

            if not lines_to_blame:
                logging.info(
                    f"No lines to blame found for {file_path} in {cve_id}. Skipping this file."
                )
                continue

            vuln_commits = blame_lines(repo, file_path, lines_to_blame, commit_id)

            for vuln_commit in vuln_commits:
                commit_url = f"{repo_url}/commit/{vuln_commit}"
                output_file = os.path.join(cve_output_dir, f"{vuln_commit}.patch")

                if os.path.exists(output_file):
                    logging.info(
                        f"Patch for CVE {cve_id}, commit {vuln_commit} already exists. Skipping."
                    )
                    cve_has_patches = True
                    continue

                vuln_patch_content = get_patch_content(commit_url)

                if vuln_patch_content:
                    with open(output_file, "w") as f:
                        f.write(vuln_patch_content)
                    logging.info(f"Saved patch for CVE {cve_id}, commit {vuln_commit}")
                    cve_has_patches = True
                else:
                    logging.warning(
                        f"Failed to get patch content for {cve_id}, commit {vuln_commit}"
                    )

        if not cve_has_patches:
            logging.warning(f"No patches were generated for CVE {cve_id}")
        if cve_has_patches:
            # Create a flag file to indicate that this CVE has been processed
            with open(processed_flag_file, "w") as f:
                f.write("")


if __name__ == "__main__":
    loggingConfig()
    analyze_vulnerabilities()
