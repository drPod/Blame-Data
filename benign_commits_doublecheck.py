import os
from constants import VECTOR_BENIGN_COMMITS_DIR, VULNERABILITY_INTRO_METADATA_DIR

benign_files = {}
vuln_files = {}

# Collect all JSON files from benign_commits
for root, _, files in os.walk(VECTOR_BENIGN_COMMITS_DIR):
    for file in files:
        if file.endswith(".json"):
            benign_files[file] = os.path.join(root, file)

# Collect all JSON files from vulnerability_intro_metadata
for root, _, files in os.walk(VULNERABILITY_INTRO_METADATA_DIR):
    for file in files:
        if file.endswith(".json"):
            vuln_files[file] = os.path.join(root, file)

# Find and delete matching files
for file in benign_files.keys():
    if file in vuln_files:
        print(f"Deleting file: {benign_files[file]}")
        os.remove(benign_files[file])
