import csv
import os
import json
import subprocess
import requests
from git import Repo
import logging
from tqdm import tqdm

# Set up logging
logging.basicConfig(
    filename="malicious_commit_analysis.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Constants
PATCH_CACHE_DIR = "patch_cache"
REPO_CACHE_DIR = "repo_cache"
COMMIT_METADATA_DIR = "commit_metadata"


def ensure_dirs():
    """Ensure all necessary directories exist."""
    for directory in [PATCH_CACHE_DIR, REPO_CACHE_DIR, COMMIT_METADATA_DIR]:
        os.makedirs(directory, exist_ok=True)


def get_cached_patch_path(commit_url):
    """Generate a unique filename for caching the patch."""
    filename = commit_url.split("/")[-1].replace("/", "_") + ".patch"
    return os.path.join(PATCH_CACHE_DIR, filename)


def get_patch_info(commit_url):
    try:
        clean_url = commit_url.split("#")[0]
        patch_url = clean_url + ".patch"
        cached_patch_path = get_cached_patch_path(clean_url)

        if os.path.exists(cached_patch_path):
            logging.info(f"Using cached patch for: {clean_url}")
            with open(cached_patch_path, "r") as patch_file:
                patch_content = patch_file.read()
        else:
            logging.info(f"Fetching patch from: {patch_url}")
            response = requests.get(patch_url)
            response.raise_for_status()
            patch_content = response.text
            with open(cached_patch_path, "w") as patch_file:
                patch_file.write(patch_content)
            logging.info(f"Saved patch to: {cached_patch_path}")

        file_changes = {}
        current_file = None
        in_changelog = False

        for line in patch_content.split("\n"):
            if line.startswith("---"):
                parts = line.split(" ")
                if len(parts) > 1:
                    current_file = parts[1][2:]
                    file_changes[current_file] = (
                        {  # This is a dictionary to store the changes for each file
                            "removed": [],
                            "added": [],
                            "context": [],
                        }
                    )
                    in_changelog = False
                else:
                    in_changelog = True
            elif not in_changelog and current_file:
                if line.startswith("-") and not line.startswith("---"):
                    file_changes[current_file]["removed"].append(line[1:])
                elif line.startswith("+") and not line.startswith("+++"):
                    file_changes[current_file]["added"].append(line[1:])
                else:
                    file_changes[current_file]["context"].append(line)
        logging.info(f"Found {len(file_changes)} files in patch")
        return file_changes
    except Exception as e:
        logging.error(f"Error in get_patch_info for {commit_url}: {str(e)}")
        return None


def get_or_create_repo(repo_url):
    repo_name = repo_url.split("/")[-1]
    repo_path = os.path.join(REPO_CACHE_DIR, repo_name)
    if not os.path.exists(repo_path):
        logging.info(f"Cloning repository: {repo_url}")
        try:
            repo = Repo.clone_from(repo_url, repo_path)
            logging.info(f"Successfully cloned repository: {repo_url}")
            return repo
        except Exception as e:
            logging.error(f"Error cloning repository {repo_url}: {str(e)}")
            return None
    else:
        try:
            repo = Repo(repo_path)
            repo.remotes.origin.pull()
            logging.info(f"Successfully updated repository: {repo_url}")
            return repo
        except Exception as e:
            logging.error(
                f"Error opening or updating repository at {repo_path}: {str(e)}"
            )
            return None


def get_commit_metadata(repo, commit_hash):
    try:
        clean_commit_hash = commit_hash.lstrip("^")
        commit = repo.commit(clean_commit_hash)
        return {
            "hash": commit.hexsha,
            "author": commit.author.name,
            "author_email": commit.author.email,
            "committed_date": commit.committed_datetime.isoformat(),
            "message": commit.message.strip(),
            "files_changed": list(commit.stats.files.keys()),
            "insertions": commit.stats.total["insertions"],
            "deletions": commit.stats.total["deletions"],
        }
    except Exception as e:
        logging.error(f"Error retrieving metadata for commit {commit_hash}: {str(e)}")
        return None


def read_existing_blame_data(blame_output_file):
    existing_data = {}
    if os.path.exists(blame_output_file):
        with open(blame_output_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_data[row["commit_id"]] = row
    return existing_data


def read_existing_metadata(cve_id):
    json_filename = os.path.join(COMMIT_METADATA_DIR, f"{cve_id}.json")
    if os.path.exists(json_filename):
        with open(json_filename, "r") as f:
            return json.load(f)
    return None


def process_commits(input_file, blame_output_file):
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

        for row in tqdm(reader, desc="Processing commits", total=total_rows):
            cve_id = row["cve_id"]
            commit_id = row["commit_id"]

            # Check if we need to process this commit
            existing_row = existing_blame_data.get(commit_id)
            existing_metadata = read_existing_metadata(cve_id)

            if (
                existing_row
                and existing_metadata
                and all(field in existing_row for field in blame_fieldnames)
            ):
                continue  # Skip if we have complete data for this commit

            project_name = row["project_name"]
            repo_url = row["repo_url"]
            commit_url = row["commit_url"]
            parent_commit_id = row["parent_commit_id"]

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


if __name__ == "__main__":
    input_file = "commits_with_parent_ids.csv"
    blame_output_file = "commits_with_blame_data.csv"
    process_commits(input_file, blame_output_file)
    print(
        f"Processing complete. Results saved to {blame_output_file} and {COMMIT_METADATA_DIR}"
    )
    print(f"Log file: malicious_commit_analysis.log")
