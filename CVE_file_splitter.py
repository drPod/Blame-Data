import sys
import math


def split_file(input_file, output_file, screen_number, total_screens=10):
    # Read all lines from the input file
    with open(input_file, "r") as f:
        lines = f.readlines()

    total_lines = len(lines)
    lines_per_screen = math.ceil(total_lines / total_screens)

    # Calculate the start and end indices for the current screen
    start_index = (screen_number - 1) * lines_per_screen
    end_index = min(screen_number * lines_per_screen, total_lines)

    # Write the selected lines to the output file
    with open(output_file, "w") as f:
        f.writelines(lines[start_index:end_index])

    print(f"Processed screen {screen_number} of {total_screens}")
    print(f"Written lines {start_index + 1} to {end_index} out of {total_lines}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <screen_number>")
        sys.exit(1)

    try:
        screen_number = int(sys.argv[1])
        if screen_number < 1 or screen_number > 10:
            raise ValueError("Screen number must be between 1 and 10")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    input_file = "All_CVEs_to_process.txt"
    output_file = "CVEs_to_process.txt"

    split_file(input_file, output_file, screen_number)
