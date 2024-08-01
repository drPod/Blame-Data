import os
import json
import numpy as np
import matplotlib.pyplot as plt
from typing import List, Dict
from constants import (
    VECTOR_VULN_INTRO_COMMITS_DIR,
    VECTOR_BENIGN_COMMITS_DIR,
)


def read_json_file(file_path: str) -> Dict:
    with open(file_path, "r") as f:
        return json.load(f)


def get_commit_lengths(folder: str) -> List[int]:
    lengths = []
    for root, dirs, files in os.walk(folder):
        for filename in files:
            if filename.endswith(".json"):
                file_path = os.path.join(root, filename)
                try:
                    data = read_json_file(file_path)
                    # Count the number of vectors (tokens) in the JSON file
                    length = len(data)
                    lengths.append(length)
                except json.JSONDecodeError:
                    print(f"Error reading JSON file: {file_path}")
                except Exception as e:
                    print(f"Unexpected error processing file {file_path}: {str(e)}")
    return lengths


def plot_length_distribution(benign_lengths: List[int], vuln_lengths: List[int]):
    all_lengths = benign_lengths + vuln_lengths

    if not all_lengths:
        print("Warning: No commit lengths found.")
        return

    percentiles = [50, 75, 90, 95, 99]
    colors = ["r", "g", "b", "c", "m"]
    thresholds = [np.percentile(all_lengths, p) for p in percentiles]

    fig, (ax1, ax2, ax3) = plt.subplots(
        3, 1, figsize=(12, 18), gridspec_kw={"height_ratios": [3, 1, 2]}
    )

    # Main plot (log scale, up to 99th percentile)
    max_x = thresholds[-1]
    bins = np.logspace(np.log10(1), np.log10(max_x), 100)

    ax1.hist(benign_lengths, bins=bins, alpha=0.5, label="Benign Commits", density=True)
    ax1.hist(
        vuln_lengths,
        bins=bins,
        alpha=0.5,
        label="Vulnerability-Introducing Commits",
        density=True,
    )

    ax1.set_xscale("log")
    ax1.set_xlabel("Commit Length (number of tokens, log scale)")
    ax1.set_ylabel("Density")
    ax1.set_title("Distribution of Commit Lengths (up to 99th percentile)")
    ax1.legend()

    for p, color, threshold in zip(percentiles, colors, thresholds):
        ax1.axvline(
            x=threshold,
            color=color,
            linestyle="--",
            label=f"{p}th percentile: {threshold:.0f}",
        )

    ax1.legend()

    # Overview plot (full range)
    ax2.hist(benign_lengths, bins=50, alpha=0.5, label="Benign Commits", density=True)
    ax2.hist(
        vuln_lengths,
        bins=50,
        alpha=0.5,
        label="Vulnerability-Introducing Commits",
        density=True,
    )

    ax2.set_xlabel("Commit Length (number of tokens)")
    ax2.set_ylabel("Density")
    ax2.set_title("Overview of Full Distribution")

    # CDF plot
    sorted_benign = np.sort(benign_lengths)
    sorted_vuln = np.sort(vuln_lengths)
    yvals_benign = np.arange(len(sorted_benign)) / float(len(sorted_benign) - 1)
    yvals_vuln = np.arange(len(sorted_vuln)) / float(len(sorted_vuln) - 1)

    ax3.plot(sorted_benign, yvals_benign, label="Benign Commits")
    ax3.plot(sorted_vuln, yvals_vuln, label="Vulnerability-Introducing Commits")
    ax3.set_xscale("log")
    ax3.set_xlabel("Commit Length (number of tokens, log scale)")
    ax3.set_ylabel("Cumulative Probability")
    ax3.set_title("Cumulative Distribution Function (CDF)")
    ax3.legend()

    for p, color, threshold in zip(percentiles, colors, thresholds):
        ax3.axvline(
            x=threshold,
            color=color,
            linestyle="--",
            label=f"{p}th percentile: {threshold:.0f}",
        )
        ax3.axhline(
            y=p / 100,
            color=color,
            linestyle=":",
        )

    ax3.legend()

    plt.tight_layout()
    plt.savefig("commit_length_distribution_with_cdf.png", dpi=300)
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

    print("\nBenign Commits Statistics:")
    print(f"Mean length: {np.mean(benign_lengths):.2f}")
    print(f"Median length: {np.median(benign_lengths):.2f}")

    print("\nVulnerability-Introducing Commits Statistics:")
    print(f"Mean length: {np.mean(vuln_lengths):.2f}")
    print(f"Median length: {np.median(vuln_lengths):.2f}")


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
