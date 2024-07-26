import csv
import json
import os
from collections import defaultdict


def process_csv(csv_file):
    repos = defaultdict(set)
    cve_to_repo = {}

    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            repo_url = row["repo_url"]
            commit_id = row["commit_id"]
            cve_id = row["cve_id"]
            repos[repo_url].add(commit_id)
            cve_to_repo[cve_id] = repo_url

    return repos, cve_to_repo


def process_vuln_intro_metadata(folder_path, repos, cve_to_repo):
    for cve_folder in os.listdir(folder_path):
        cve_path = os.path.join(folder_path, cve_folder)
        if os.path.isdir(cve_path):
            repo_url = cve_to_repo.get(cve_folder)
            if repo_url:
                for commit_file in os.listdir(cve_path):
                    if commit_file.endswith(".json"):
                        commit_id = commit_file[:-5]  # Remove .json extension
                        repos[repo_url].add(commit_id)


def main():
    input_csv = "commits_with_parent_ids.csv"
    output_json = "organized_commits.json"
    vuln_intro_folder = "vulnerability_intro_metadata"

    repos, cve_to_repo = process_csv(input_csv)
    process_vuln_intro_metadata(vuln_intro_folder, repos, cve_to_repo)

    # Convert sets to lists for JSON serialization
    repos_json = {repo: list(commits) for repo, commits in repos.items()}

    with open(output_json, "w") as f:
        json.dump(repos_json, f, indent=2)

    print(f"Processed data has been written to {output_json}")


if __name__ == "__main__":
    main()
