import os
import json
import random
import logging
import subprocess
import requests
from git import Repo
from tqdm import tqdm

from constants import (
    BENIGN_COMMITS_DIR,
    BENIGN_PATCHES_DIR,
    REPO_CACHE_DIR,
    loggingConfig,
)

from ensure_directories import ensure_dirs

BENIGN_COMMITS_PER_VULN = 5


def get_benign_commits(repo, excluded_commits, num_benign):
    all_commits = list(repo.iter_commits("--all"))
    benign_commits = [
        commit for commit in all_commits if commit.hexsha not in excluded_commits
    ]
    return random.sample(benign_commits, min(num_benign, len(benign_commits)))


def download_patch(repo_url, commit_id, output_path):
    if os.path.exists(output_path):
        logging.info(
            f"Patch file already exists for commit {commit_id}. Skipping download."
        )
        return True

    patch_url = f"{repo_url}/commit/{commit_id}.patch"

    # Try wget first
    try:
        subprocess.run(["wget", "-q", "-O", output_path, patch_url], check=True)
        return True
    except subprocess.CalledProcessError:
        logging.warning(f"wget failed for {patch_url}. Falling back to requests.")
    except FileNotFoundError:
        logging.warning("wget not found. Falling back to requests.")

    # Fall back to requests
    try:
        response = requests.get(patch_url)
        response.raise_for_status()
        with open(output_path, "wb") as f:
            f.write(response.content)
        return True
    except requests.RequestException as e:
        logging.error(f"Failed to download patch for {commit_id}: {str(e)}")
        return False


def read_patch_file(file_path):
    encodings = ["utf-8", "latin-1", "ascii"]
    for encoding in encodings:
        try:
            with open(file_path, "r", encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    logging.error(f"Failed to read patch file with any encoding: {file_path}")
    return None


def get_patch_info(patch_content):
    if patch_content is None:
        return {}

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


def count_existing_benign_commits(repo_name):
    repo_benign_dir = os.path.join(BENIGN_COMMITS_DIR, repo_name)
    if not os.path.exists(repo_benign_dir):
        return 0
    return len([f for f in os.listdir(repo_benign_dir) if f.endswith(".json")])


def count_existing_patch_files(repo_name):
    repo_patches_dir = os.path.join(BENIGN_PATCHES_DIR, repo_name)
    if not os.path.exists(repo_patches_dir):
        return 0
    return len([f for f in os.listdir(repo_patches_dir) if f.endswith(".patch")])


def process_benign_commits():
    ensure_dirs()
    loggingConfig()

    with open("organized_commits.json", "r") as f:
        organized_commits = json.load(f)

    for repo_url, commits in tqdm(
        organized_commits.items(), desc="Processing repositories"
    ):
        repo_name = repo_url.split("/")[-1]
        repo_path = os.path.join(REPO_CACHE_DIR, repo_name)

        if not os.path.exists(repo_path):
            logging.warning(f"Repository not found: {repo_path}. Skipping.")
            continue

        try:
            repo = Repo(repo_path)
        except Exception as e:
            logging.error(f"Failed to load repository {repo_path}: {str(e)}")
            continue

        num_benign_commits_required = len(commits) * BENIGN_COMMITS_PER_VULN
        existing_benign_commits = count_existing_benign_commits(repo_name)
        existing_patch_files = count_existing_patch_files(repo_name)
        num_benign_commits_to_process = max(
            0,
            num_benign_commits_required
            - max(existing_benign_commits, existing_patch_files),
        )

        if num_benign_commits_to_process == 0:
            logging.info(
                f"Repository {repo_name} already has sufficient benign commits and patch files. Skipping."
            )
            continue

        logging.info(
            f"Processing {num_benign_commits_to_process} additional benign commits for {repo_name}"
        )

        try:
            benign_commits = get_benign_commits(
                repo, set(commits), num_benign_commits_to_process
            )
        except Exception as e:
            logging.error(f"Failed to get benign commits for {repo_path}: {str(e)}")
            continue

        # Create repository-specific directories for patches and benign commits
        repo_patches_dir = os.path.join(BENIGN_PATCHES_DIR, repo_name)
        repo_benign_commits_dir = os.path.join(BENIGN_COMMITS_DIR, repo_name)
        os.makedirs(repo_patches_dir, exist_ok=True)
        os.makedirs(repo_benign_commits_dir, exist_ok=True)

        for commit in benign_commits:
            commit_id = commit.hexsha

            # Check if JSON file already exists
            json_file = os.path.join(repo_benign_commits_dir, f"{commit_id}.json")
            if os.path.exists(json_file):
                logging.info(
                    f"JSON file already exists for commit {commit_id}. Skipping processing."
                )
                continue

            # Download and save patch content
            patch_file = os.path.join(repo_patches_dir, f"{commit_id}.patch")
            if download_patch(repo_url, commit_id, patch_file):
                logging.info(f"Downloaded patch for benign commit: {commit_id}")

                # Read the patch content
                patch_content = read_patch_file(patch_file)
                if patch_content is None:
                    continue

                # Process patch info
                file_changes = get_patch_info(patch_content)

                # Create JSON data
                json_data = {
                    "cve_id": "benign",  # Use "benign" as a placeholder for CVE
                    "commit_id": commit_id,
                    "file_changes": file_changes,
                }

                # Save JSON data in repository-specific subfolder
                try:
                    with open(json_file, "w") as f:
                        json.dump(json_data, f, indent=2)
                except IOError as e:
                    logging.error(f"Failed to write JSON file {json_file}: {str(e)}")

            else:
                logging.warning(
                    f"Failed to download patch for benign commit: {commit_id}"
                )

    logging.info("Benign commit processing completed.")


if __name__ == "__main__":
    process_benign_commits()
