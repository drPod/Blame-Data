import os
import json
from collections import Counter
from constants import BENIGN_COMMITS_DIR, VULNERABILITY_INTRO_METADATA_DIR


def analyze_file_extensions(directory):
    extension_counter = Counter()
    no_extension_counter = Counter()

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                with open(file_path, "r") as f:
                    try:
                        commit_data = json.load(f)
                        for changed_file in commit_data.get("file_changes", {}).keys():
                            _, ext = os.path.splitext(changed_file)
                            if ext:
                                extension_counter[ext] += 1
                            else:
                                filename = os.path.basename(changed_file)
                                no_extension_counter[filename] += 1
                    except json.JSONDecodeError:
                        print(f"Error decoding JSON in file: {file_path}")

    return extension_counter, no_extension_counter


def main():
    benign_extensions, benign_no_ext = analyze_file_extensions(BENIGN_COMMITS_DIR)
    vuln_extensions, vuln_no_ext = analyze_file_extensions(
        VULNERABILITY_INTRO_METADATA_DIR
    )

    # Combine results
    all_extensions = benign_extensions + vuln_extensions
    all_no_ext = benign_no_ext + vuln_no_ext

    # Combine all results into a single list and sort once
    all_results = [(ext, count) for ext, count in all_extensions.items()] + [
        (filename, count) for filename, count in all_no_ext.items()
    ]
    all_results.sort(key=lambda x: x[1], reverse=True)

    # Write results to file
    with open("file_extension_analysis.txt", "w") as f:
        f.write("File Extensions and Files without Extensions:\n")
        for item, count in all_results:
            f.write(f"{item}: {count}\n")

    print("Analysis complete. Results written to file_extension_analysis.txt")


if __name__ == "__main__":
    main()
