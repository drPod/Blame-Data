# pip install -r requirements_for_main3.txt

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

# Language-specific tokenizers
from pycparser import c_parser  # For C
from clang.cindex import Index, CursorKind  # For C++, Objective-C
from javalang import tokenize as java_tokenize  # For Java
from typescript import tokenize as ts_tokenize  # For TypeScript
from js2py import parse_js  # For JavaScript
from rubymarshal.reader import UnmarshalReader  # For Ruby
from xml.etree.ElementTree import XML  # For XML
from cssutils import parseString  # For CSS
from sqlparse import parse as sql_parse  # For SQL
from yaml import safe_load  # For YAML
from configparser import ConfigParser  # For .ini and some .conf files
from markdown import markdown  # For Markdown


def tokenize_cpp(code: str) -> List[str]:
    index = Index.create()
    tu = index.parse("tmp.cpp", args=["-std=c++11"], unsaved_files=[("tmp.cpp", code)])
    return [token.spelling for token in tu.get_tokens()]


def tokenize_typescript(code: str) -> List[str]:
    return [token.value for token in ts_tokenize(code)]


def tokenize_xml(code: str) -> List[str]:
    return [elem.tag for elem in XML(code)]


def tokenize_css(code: str) -> List[str]:
    return [rule.selectorText for rule in parseString(code).cssRules]


def tokenize_sql(code: str) -> List[str]:
    return [token.value for token in sql_parse(code)]


def tokenize_yaml(code: str) -> List[str]:
    return [key for key in safe_load(code)]


def tokenize_ini(code: str) -> List[str]:
    parser = ConfigParser()
    parser.read_string(code)
    return [section for section in parser.sections()]


def tokenize_markdown(code: str) -> List[str]:
    return [token for token in markdown(code)]


def tokenize_python(code: str) -> List[str]:
    return [token.value for token in src_to_tokens(code)]


def tokenize_c(code: str) -> List[str]:
    parser = c_parser.CParser()
    return [token for _, token in parser.parse(code).children()]


def tokenize_php(code: str) -> List[str]:
    return [token.value for token in src_to_tokens(code, "php")]


def tokenize_java(code: str) -> List[str]:
    return [token.value for token in java_tokenize(code)]


def tokenize_javascript(code: str) -> List[str]:
    return [token.value for token in parse_js(code)]


def tokenize_ruby(code: str) -> List[str]:
    return [token for token in UnmarshalReader(code).read()]


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
    tokenization_loggingConfig()
    tokenizers = {
        "text/x-c++src": tokenize_cpp,
        "text/x-c++hdr": tokenize_cpp,
        "c++": tokenize_cpp,
        ".cpp": tokenize_cpp,
        ".hpp": tokenize_cpp,
        "text/typescript": tokenize_typescript,
        "typescript": tokenize_typescript,
        ".ts": tokenize_typescript,
        "text/xml": tokenize_xml,
        "xml": tokenize_xml,
        ".xml": tokenize_xml,
        "text/css": tokenize_css,
        "css": tokenize_css,
        ".css": tokenize_css,
        "text/x-sql": tokenize_sql,
        "sql": tokenize_sql,
        ".sql": tokenize_sql,
        "text/yaml": tokenize_yaml,
        "yaml": tokenize_yaml,
        ".yaml": tokenize_yaml,
        "text/x-ini": tokenize_ini,
        "ini": tokenize_ini,
        ".ini": tokenize_ini,
        "text/markdown": tokenize_markdown,
        "markdown": tokenize_markdown,
        ".md": tokenize_markdown,
        "text/x-python": tokenize_python,
        "python": tokenize_python,
        ".py": tokenize_python,
        "text/x-csrc": tokenize_c,
        "c": tokenize_c,
        ".c": tokenize_c,
        "text/x-php": tokenize_php,
        "php": tokenize_php,
        ".php": tokenize_php,
        "text/x-java": tokenize_java,
        "java": tokenize_java,
        ".java": tokenize_java,
        "text/javascript": tokenize_javascript,
        "javascript": tokenize_javascript,
        ".js": tokenize_javascript,
        "text/x-ruby": tokenize_ruby,
        "ruby": tokenize_ruby,
        ".rb": tokenize_ruby,
        "text/plain": tokenize_plain_text,
        "text": tokenize_plain_text,
        ".txt": tokenize_plain_text,
        ".h": tokenize_cpp,
        "changelog": tokenize_plain_text,
        "readme": tokenize_plain_text,
        "license": tokenize_plain_text,
        "copy": tokenize_plain_text,
        "copying": tokenize_plain_text,
        "copyright": tokenize_plain_text,
        ".jsx": tokenize_javascript,
        ".tsx": tokenize_typescript,
        ".conf": tokenize_ini,
        ".properties": tokenize_ini,
        ".config": tokenize_ini,
        ".mdown": tokenize_markdown,
        ".mkd": tokenize_markdown,
        ".mkdn": tokenize_markdown,
        ".mdwn": tokenize_markdown,
        ".mdtxt": tokenize_markdown,
        ".mdtext": tokenize_markdown,
        ".text": tokenize_markdown,
        ".Rmd": tokenize_markdown,
        ".rmd": tokenize_markdown,
        ".rst": tokenize_markdown,
        ".rest": tokenize_markdown,
        ".txt": tokenize_markdown,
        ".textile": tokenize_markdown,
        ".pod": tokenize_markdown,
    }

    try:
        if file_type in tokenizers:
            # Use the appropriate tokenizer
            return tokenizers[file_type](code)
        else:
            # Use Pygments to tokenize the code
            lexer = get_pygments_lexer(file_type, code)
            return [token[1] for token in lex(code, lexer)]
    except Exception as e:
        logging.error(f"Error tokenizing code: {e}")
        # If all else fails, tokenize as plain text
        return tokenize_plain_text(code)


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
