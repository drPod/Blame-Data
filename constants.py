import logging
import os

PATCH_CACHE_DIR = "patch_cache"
REPO_CACHE_DIR = "repo_cache"
COMMIT_METADATA_DIR = "commit_metadata"
VULNERABILITY_PATCHES_DIR = "vulnerability_patches"


def loggingConfig():
    # Set up logging
    logging.basicConfig(
        filename="malicious_commit_analysis.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
