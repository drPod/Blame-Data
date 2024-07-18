import logging
from constants import loggingConfig
from find_vuln_intro_commits import analyze_vulnerabilities
from process_vuln_patches import process_vuln_patches
from check_duplicates import check_duplicates


def main():
    loggingConfig()
    logging.info("Starting vulnerability analysis process...")

    logging.info("Step 1: Finding vulnerability-introducing commits...")
    analyze_vulnerabilities()

    logging.info("Step 2: Processing vulnerability patches...")
    process_vuln_patches()

    logging.info("Step 3: Checking for duplicates...")
    check_duplicates()

    logging.info("Vulnerability analysis process completed.")


if __name__ == "__main__":
    main()
