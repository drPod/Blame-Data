import os
import logging

from constants import (
    PATCH_CACHE_DIR,
    REPO_CACHE_DIR,
    COMMIT_METADATA_DIR,
    VULNERABILITY_PATCHES_DIR,
    VULNERABILITY_INTRO_METADATA_DIR,
    BENIGN_COMMITS_DIR,
    BENIGN_PATCHES_DIR,
    TOKENIZED_BENIGN_COMMITS_DIR,
    TOKENIZED_VULN_INTRO_COMMITS_DIR,
    VECTOR_BENIGN_COMMITS_DIR,
    VECTOR_VULN_INTRO_COMMITS_DIR,
    PADDED_BENIGN_COMMITS_DIR,
    PADDED_VULN_INTRO_COMMITS_DIR,
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
        BENIGN_COMMITS_DIR,
        BENIGN_PATCHES_DIR,
        TOKENIZED_BENIGN_COMMITS_DIR,
        TOKENIZED_VULN_INTRO_COMMITS_DIR,
        VECTOR_BENIGN_COMMITS_DIR,
        VECTOR_VULN_INTRO_COMMITS_DIR,
        PADDED_BENIGN_COMMITS_DIR,
        PADDED_VULN_INTRO_COMMITS_DIR,
    ]:
        os.makedirs(directory, exist_ok=True)
        logging.info(f"Directory {directory} exists.")
    logging.info("All directories exist.")
