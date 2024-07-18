import os
import json
import logging
from tqdm import tqdm

# Assuming you have a constants.py file with COMMIT_METADATA_DIR defined
from constants import COMMIT_METADATA_DIR, loggingConfig


def delete_used_context_files():
    loggingConfig()
    logging.info(f"Scanning directory: {COMMIT_METADATA_DIR}")

    deleted_count = 0
    total_files = sum(1 for _ in os.listdir(COMMIT_METADATA_DIR) if _.endswith(".json"))

    for filename in tqdm(
        os.listdir(COMMIT_METADATA_DIR), total=total_files, desc="Scanning files"
    ):
        if filename.endswith(".json"):
            file_path = os.path.join(COMMIT_METADATA_DIR, filename)
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)

                delete_file = False
                for file_info in data.get("file_changes", {}).values():
                    if file_info.get("used_context_lines", False):
                        delete_file = True
                        break

                if delete_file:
                    os.remove(file_path)
                    deleted_count += 1
                    logging.info(f"Deleted file: {filename}")

            except json.JSONDecodeError:
                logging.error(f"Error decoding JSON in file: {filename}")
            except Exception as e:
                logging.error(f"Error processing file {filename}: {str(e)}")

    logging.info(f"Deleted {deleted_count} files out of {total_files} total files.")


if __name__ == "__main__":
    delete_used_context_files()
