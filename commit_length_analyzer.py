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
from ensure_directories import ensure_dirs


def get_commit_lengths(folder: str) -> List[int]:
    lengths = []
    for filename in os.listdir(folder):
        if filename.endswith(".json"):
            file_path = os.path.join(folder, filename)
            data = read_json_file(file_path)
            for changes in data["file_changes"].values():
                lengths.append(len(changes["added_lines"]))
                lengths.append(len(changes["removed_lines"]))
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
    for p, color in zip(percentiles, colors):
        threshold = np.percentile(all_lengths, p)
        plt.axvline(
            x=threshold,
            color=color,
            linestyle="--",
            label=f"{p}th percentile: {threshold:.0f}",
        )

    plt.legend()
    plt.tight_layout()
    plt.savefig("commit_length_distribution.png")
    plt.close()


def print_statistics(benign_lengths: List[int], vuln_lengths: List[int]):
    all_lengths = benign_lengths + vuln_lengths

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

    plot_length_distribution(benign_lengths, vuln_lengths)
    print_statistics(benign_lengths, vuln_lengths)


if __name__ == "__main__":
    ensure_dirs()
    main()
