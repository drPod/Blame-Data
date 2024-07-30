import mimetypes
import magic
import os
import logging
from constants import tokenization_loggingConfig


def is_text_file(file_content):
    return all(ord(c) < 128 for c in file_content)


def determine_file_type_using_python_magic(file_path, file_content):
    tokenization_loggingConfig()
    logger = logging.getLogger(__name__)

    logger.info(f"Using python-magic to determine the type of {file_path}")

    try:
        if not file_content["added_lines"] and not file_content["removed_lines"]:
            logger.warning(f"File {file_path} appears to be empty")
            return "text/plain"  # Default to plain text for empty files

        # Try to use the first non-empty line from added_lines or removed_lines
        content_line = next(
            (
                line
                for line in file_content["added_lines"] + file_content["removed_lines"]
                if line.strip()
            ),
            "",
        )

        if not content_line:
            logger.warning(f"No non-empty lines found in {file_path}")
            return "text/plain"  # Default to plain text if no non-empty lines

        file_type = magic.from_buffer(content_line.encode(), mime=True)

        if file_type.startswith("text/") and is_text_file(content_line):
            return "text/plain"

        return (
            file_type if file_type else "application/octet-stream"
        )  # Default to binary if type couldn't be determined

    except Exception as e:
        logger.error(f"Error determining file type for {file_path}: {str(e)}")
        return "application/octet-stream"  # Default to binary in case of any error


def determine_file_type(file_path, file_content):
    tokenization_loggingConfig()

    # Initialize mimetypes
    mimetypes.init()

    # Get the file extension
    _, extension = os.path.splitext(file_path)

    # Use mimetypes to guess the type
    mime_type, _ = mimetypes.guess_type(file_path)

    if mime_type:
        logging.info(f"Using mimetypes to determine the type of {file_path}")
        return mime_type

    return determine_file_type_using_python_magic(file_path, file_content)
