# Make sure all the directories exist

import os
from constants import PATCH_CACHE_DIR, REPO_CACHE_DIR, COMMIT_METADATA_DIR


def ensure_dirs():
    """Ensure all necessary directories exist."""
    for directory in [PATCH_CACHE_DIR, REPO_CACHE_DIR, COMMIT_METADATA_DIR]:
        os.makedirs(directory, exist_ok=True)
