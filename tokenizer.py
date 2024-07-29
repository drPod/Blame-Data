import re
import json
import os
import logging
from typing import Dict, List
from constants import tokenization_loggingConfig
from file_type_detector import determine_file_type
from tokenize_rt import src_to_tokens
from pygments import lex
from pygments.lexers import get_lexer_by_name, guess_lexer, get_lexer_for_mimetype
from pygments.util import ClassNotFound
from pycparser import c_lexer
from phply import lexer as php_lexer


def tokenize_c(code: str) -> List[str]:
    c_lex = c_lexer.CLexer()
    c_lex.build()
    c_lex.input(code)
    return [tok.value for tok in c_lex]


def tokenize_php(code: str) -> List[str]:
    php_lex = php_lexer.lexer.clone()
    php_lex.input(code)
    return [tok.value for tok in php_lex]


def tokenize_plain_text(code: str) -> List[str]:
    return re.findall(r"\w+|[^\w\s]", code)


def get_pygments_lexer(file_type: str, code: str):
    try:
        # Try to get lexer by name
        return get_lexer_by_name(file_type, stripall=True)
    except ClassNotFound:
        try:
            # If that fails, try to get lexer by mime type
            return get_lexer_for_mimetype(file_type, stripall=True)
        except ClassNotFound:
            # If both fail, guess the lexer based on the code content
            return guess_lexer(code)


def tokenize_code(code: str, file_type: str) -> List[str]:
    if file_type == "text/x-python" or file_type == "python":
        return [token.src for token in src_to_tokens(code)]
    elif file_type in ["text/x-csrc", "text/x-chdr", "c"]:
        return tokenize_c(code)
    elif file_type in ["text/x-php", "php"]:
        return tokenize_php(code)
    elif file_type in ["text", "English text"]:
        return tokenize_plain_text(code)
    else:
        lexer = get_pygments_lexer(file_type, code)
        return [token[1] for token in lex(code, lexer)]


def subtokenize(tokens: List[str]) -> List[str]:
    subtokens = []
    for token in tokens:
        # Split camelCase and PascalCase
        subtokens.extend(
            re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\W|$)|\d+", token)
        )

    # Convert to lowercase for consistency
    return [subtoken.lower() for subtoken in subtokens if subtoken]


def process_file_changes(
    file_changes: Dict[str, Dict[str, List[str]]]
) -> Dict[str, Dict[str, List[List[str]]]]:
    tokenized_changes = {}
    for file_path, changes in file_changes.items():
        file_type = determine_file_type(file_path, changes)

        tokenized_changes[file_path] = {
            "added_lines": [
                subtokenize(tokenize_code(line, file_type))
                for line in changes["added_lines"]
            ],
            "removed_lines": [
                subtokenize(tokenize_code(line, file_type))
                for line in changes["removed_lines"]
            ],
        }
    return tokenized_changes


def tokenize_commit(commit_data: Dict) -> Dict:
    tokenized_commit = commit_data.copy()
    tokenized_commit["file_changes"] = process_file_changes(commit_data["file_changes"])
    return tokenized_commit


def tokenize_directory(input_dir: str, output_dir: str):
    tokenization_loggingConfig()

    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.endswith(".json"):
                input_path = os.path.join(root, file)
                relative_path = os.path.relpath(input_path, input_dir)
                output_path = os.path.join(output_dir, relative_path)

                os.makedirs(os.path.dirname(output_path), exist_ok=True)

                with open(input_path, "r") as f:
                    commit_data = json.load(f)

                tokenized_data = tokenize_commit(commit_data)

                with open(output_path, "w") as f:
                    json.dump(tokenized_data, f, indent=2)

                logging.info(f"Tokenized and saved: {output_path}")
