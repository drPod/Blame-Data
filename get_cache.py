import os
import logging
import requests
from git import Repo

from constants import REPO_CACHE_DIR, PATCH_CACHE_DIR
from constants import loggingConfig


def get_cached_patch_path(commit_url):
    """Generate a unique filename for caching the patch."""
    filename = commit_url.split("/")[-1].replace("/", "_") + ".patch"
    return os.path.join(PATCH_CACHE_DIR, filename)


def get_or_create_repo(repo_url):
    """Get or create a repository object."""
    loggingConfig()
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


def get_patch_info(commit_url):
    """Get the changes made in a commit
    Args:
    commit_url (str): URL to the commit
    Returns:
    dict: A dictionary containing the changes made in the commit
    """
    loggingConfig()
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

        for section in patch_content.split("diff --git")[1:]:
            lines = section.split("\n")
            filename = lines[0].split()[-1].lstrip("b/")
            changes = []
            malicious_lines = []
            context_lines = []
            used_context_lines = False
            in_hunk = False
            added_line_index = -1

            for i, line in enumerate(lines):
                if line.startswith("@@"):
                    in_hunk = True
                    context_lines = []
                elif in_hunk:
                    if line.startswith("-"):
                        malicious_lines.append(line)
                        changes.append(line)
                    elif line.startswith("+"):
                        changes.append(line)
                        added_line_index = i
                    else:
                        context_lines.append(line)

            if not malicious_lines and added_line_index != -1:
                used_context_lines = True
                start = max(0, added_line_index - 3)
                end = min(len(lines), added_line_index + 3)
                malicious_lines = [
                    line
                    for line in lines[start:end]
                    if not line.startswith(("+", "@@", "diff", "index"))
                ]

            file_changes[filename] = {
                "changes": changes,
                "malicious_lines": malicious_lines,
                "used_context_lines": used_context_lines,
            }

        logging.info(f"Found {len(file_changes)} files in patch")
        logging.info(f"FILE CHANGES: {file_changes}")
        return file_changes

    except Exception as e:
        logging.error(f"Error in get_patch_info for {commit_url}: {str(e)}")
        return None


def get_commit_metadata(repo, commit_hash):
    """Get metadata for a commit.
    Args:
        repo (git.Repo): Repository object
        commit_hash (str): Hash of the commit
    Returns:
        dict: A dictionary containing metadata for the commit
    """
    loggingConfig()
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
