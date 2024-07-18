import os
import logging

from constants import (
    PATCH_CACHE_DIR,
    REPO_CACHE_DIR,
    COMMIT_METADATA_DIR,
    VULNERABILITY_PATCHES_DIR,
    VULNERABILITY_INTRO_METADATA_DIR,
)
from constants import loggingConfig


def ensure_dirs():
    """Ensure all necessary directories exist."""
    loggingConfig()
    for directory in [
        PATCH_CACHE_DIR,
        REPO_CACHE_DIR,
        COMMIT_METADATA_DIR,
        VULNERABILITY_PATCHES_DIR,
        VULNERABILITY_INTRO_METADATA_DIR,
    ]:
        os.makedirs(directory, exist_ok=True)
        logging.info(f"Directory {directory} exists.")
    logging.info("All directories exist.")


# The function ensure_dirs() creates the directories specified in the constants file if they do not already exist. This function is used in the process_commits.py script to ensure that the required directories are available before processing the commits.
