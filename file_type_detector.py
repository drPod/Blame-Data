import mimetypes
import magic
import os
import logging
from constants import tokenization_loggingConfig


def is_text_file(file_content):
    return all(ord(c) < 128 for c in file_content)


def determine_file_type_using_python_magic(file_path, file_content):
    tokenization_loggingConfig()

    # If mimetype couldn't determine the type, use python-magic
    logging.info(f"Using python-magic to determine the type of {file_path}")
    file_type = magic.from_buffer(file_content["added_lines"][0].encode(), mime=True)

    if file_type.startswith("text/") and is_text_file(file_content["added_lines"][0]):
        return "English text"

    return file_type if file_type else "Unknown"


def determine_file_type(file_path, file_content):
    tokenization_loggingConfig()

    # Initialize mimetypes
    mimetypes.init()

    # Get the file extension
    _, extension = os.path.splitext(file_path)

    # Special cases
    if extension.lower() == ".h":
        return "C Header"
    elif file_path.lower() == "changelog":
        return "English text"
    elif file_path.lower() == "readme" or file_path.lower().startswith("readme"):
        return "English text"
    elif file_path.lower().startswith("license"):
        return "English text"
    elif file_path.lower().startswith("copy"):
        return "English text"
    elif file_path.lower().endswith("makefile"):
        return "Makefile"
    elif file_path.lower().endswith("dockerfile"):
        return "Dockerfile"
    elif file_path.lower().endswith("txt"):
        return determine_file_type_using_python_magic(file_path, file_content)

    # Use mimetypes to guess the type
    mime_type, _ = mimetypes.guess_type(file_path)

    if mime_type:
        logging.info(f"Using mimetypes to determine the type of {file_path}")
        return mime_type

    return determine_file_type_using_python_magic(file_path, file_content)
