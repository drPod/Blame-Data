# This script is supposed to remove all the duplicate json files from the vulnerability_intro_metadata directory.

import os
from constants import VULNERABILITY_INTRO_METADATA_DIR


def remove_duplicate_json_files(root_dir):
    """Remove duplicate JSON files across all subdirectories based on filename."""
    json_files = {}
    removed_count = 0

    # Walk through all subdirectories
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith(".json"):
                full_path = os.path.join(dirpath, filename)

                if filename in json_files:
                    # This is a duplicate, remove it
                    os.remove(full_path)
                    print(f"Removed duplicate file: {full_path}")
                    removed_count += 1
                else:
                    # This is the first occurrence of this filename
                    json_files[filename] = full_path

    print(f"Removed {removed_count} duplicate JSON files.")


if __name__ == "__main__":
    root_directory = VULNERABILITY_INTRO_METADATA_DIR
    remove_duplicate_json_files(root_directory)
