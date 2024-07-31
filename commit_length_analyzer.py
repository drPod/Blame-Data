import os
import json
import numpy as np
import matplotlib.pyplot as plt
from typing import List, Dict
from vectorized_commit_processor import read_json_file
from constants import (
    VECTOR_VULN_INTRO_COMMITS_DIR,
    VECTOR_BENIGN_COMMITS_DIR,
)


def get_commit_lengths(folder: str) -> List[int]:
    lengths = []
    for root, dirs, files in os.walk(folder):
        for filename in files:
            if filename.endswith(".json"):
                file_path = os.path.join(root, filename)
                try:
                    data = read_json_file(file_path)
                    for changes in data["file_changes"].values():
                        lengths.append(len(changes["added_lines"]))
                        lengths.append(len(changes["removed_lines"]))
                except json.JSONDecodeError:
                    print(f"Error reading JSON file: {file_path}")
                except KeyError:
                    print(f"Unexpected JSON structure in file: {file_path}")
    return lengths


def plot_length_distribution(benign_lengths: List[int], vuln_lengths: List[int]):
    plt.figure(figsize=(12, 6))

    # Plot histograms
    plt.hist(benign_lengths, bins=50, alpha=0.5, label="Benign Commits")
    plt.hist(
        vuln_lengths, bins=50, alpha=0.5, label="Vulnerability-Introducing Commits"
    )

    plt.xlabel("Commit Length (number of vectors)")
    plt.ylabel("Frequency")
    plt.title("Distribution of Commit Lengths")
    plt.legend()

    # Add vertical lines for different percentiles
    percentiles = [50, 75, 90, 95, 99]
    colors = ["r", "g", "b", "c", "m"]

    all_lengths = benign_lengths + vuln_lengths
    if all_lengths:
        for p, color in zip(percentiles, colors):
            threshold = np.percentile(all_lengths, p)
            plt.axvline(
                x=threshold,
                color=color,
                linestyle="--",
                label=f"{p}th percentile: {threshold:.0f}",
            )
    else:
        print("Warning: No commit lengths found.")

    plt.legend()
    plt.tight_layout()
    plt.savefig("commit_length_distribution.png")
    plt.close()


def print_statistics(benign_lengths: List[int], vuln_lengths: List[int]):
    all_lengths = benign_lengths + vuln_lengths

    if not all_lengths:
        print("No commit lengths found. Unable to compute statistics.")
        return

    print("Overall Statistics:")
    print(f"Mean length: {np.mean(all_lengths):.2f}")
    print(f"Median length: {np.median(all_lengths):.2f}")
    print(f"Standard deviation: {np.std(all_lengths):.2f}")

    percentiles = [50, 75, 90, 95, 99]
    for p in percentiles:
        threshold = np.percentile(all_lengths, p)
        print(f"{p}th percentile: {threshold:.0f}")


def main():
    benign_lengths = get_commit_lengths(VECTOR_BENIGN_COMMITS_DIR)
    vuln_lengths = get_commit_lengths(VECTOR_VULN_INTRO_COMMITS_DIR)

    if not benign_lengths and not vuln_lengths:
        print("No commit data found. Please check your input directories.")
        return

    plot_length_distribution(benign_lengths, vuln_lengths)
    print_statistics(benign_lengths, vuln_lengths)


if __name__ == "__main__":
    main()
