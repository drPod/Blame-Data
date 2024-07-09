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
