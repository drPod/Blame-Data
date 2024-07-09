from process_commits import process_commits
from constants import COMMIT_METADATA_DIR

if __name__ == "__main__":
    input_file = "commits_with_parent_ids.csv"
    blame_output_file = "commits_with_blame_data.csv"
    process_commits(input_file, blame_output_file)
    print(
        f"Processing complete. Results saved to {blame_output_file} and {COMMIT_METADATA_DIR}"
    )
    print(f"Log file: malicious_commit_analysis.log")
