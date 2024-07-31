import logging

PATCH_CACHE_DIR = "patch_cache"
REPO_CACHE_DIR = "repo_cache"
COMMIT_METADATA_DIR = "commit_metadata"
VULNERABILITY_PATCHES_DIR = "vulnerability_patches"
VULNERABILITY_INTRO_METADATA_DIR = (
    "vulnerability_intro_metadata"  # vulnerability introducing metadata
)
BENIGN_COMMITS_DIR = "benign_commits"
BENIGN_PATCHES_DIR = "benign_patches"

TOKENIZED_BENIGN_COMMITS_DIR = "tokenized_benign_commits"
TOKENIZED_VULN_INTRO_COMMITS_DIR = "tokenized_vuln_intro_commits"

VECTOR_BENIGN_COMMITS_DIR = "vector_benign_commits_dir"
VECTOR_VULN_INTRO_COMMITS_DIR = "vector_vuln_intro_commits_dir"


def loggingConfig():
    logging.basicConfig(
        filename="malicious_commit_analysis.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def tokenization_loggingConfig():
    logging.basicConfig(
        filename="tokenization.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )