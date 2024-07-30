# pip install pycparser clang javalang js2py cssutils sqlparse pygments pyyaml markdown configparser

import re
import json
import os
import logging
from typing import Dict, List, Any
from constants import tokenization_loggingConfig
from file_type_detector import determine_file_type
from tokenize_rt import src_to_tokens
from pygments import lex
from pygments.lexers import get_lexer_by_name, guess_lexer, get_lexer_for_mimetype
from pygments.util import ClassNotFound

# Language-specific tokenizers
from pycparser import c_parser  # For C
from clang.cindex import Index, CursorKind  # For C++, Objective-C
from javalang.tokenizer import tokenize as java_tokenize  # For Java
from js2py import parse_js  # For JavaScript
from xml.etree.ElementTree import XML  # For XML
from cssutils import parseString  # For CSS
from sqlparse import parse as sql_parse  # For SQL
from yaml import safe_load  # For YAML
from configparser import ConfigParser  # For .ini and some .conf files
from markdown import markdown  # For Markdown


class CodeTokenizer:
    def __init__(self):
        self.logger = self._setup_logger()
        self.tokenizers = self._setup_tokenizers()

    def _setup_logger(self) -> logging.Logger:
        tokenization_loggingConfig()
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        return logger

    def _setup_tokenizers(self) -> Dict[str, Any]:
        return {
            "text/x-c++src": self.tokenize_cpp,
            "text/x-c++hdr": self.tokenize_cpp,
            "c++": self.tokenize_cpp,
            ".cpp": self.tokenize_cpp,
            ".hpp": self.tokenize_cpp,
            ".hxx": self.tokenize_cpp,
            ".hh": self.tokenize_cpp,
            "text/xml": self.tokenize_xml,
            "xml": self.tokenize_xml,
            ".xml": self.tokenize_xml,
            "text/css": self.tokenize_css,
            "css": self.tokenize_css,
            ".css": self.tokenize_css,
            "text/x-sql": self.tokenize_sql,
            "sql": self.tokenize_sql,
            ".sql": self.tokenize_sql,
            "text/yaml": self.tokenize_yaml,
            "yaml": self.tokenize_yaml,
            ".yaml": self.tokenize_yaml,
            "text/x-ini": self.tokenize_ini,
            "ini": self.tokenize_ini,
            ".ini": self.tokenize_ini,
            "text/markdown": self.tokenize_markdown,
            "markdown": self.tokenize_markdown,
            ".md": self.tokenize_markdown,
            "text/x-csrc": self.tokenize_c,
            "c": self.tokenize_c,
            ".c": self.tokenize_c,
            "text/x-php": self.tokenize_php,
            "php": self.tokenize_php,
            ".php": self.tokenize_php,
            "text/x-java": self.tokenize_java,
            "java": self.tokenize_java,
            ".java": self.tokenize_java,
            "text/javascript": self.tokenize_javascript,
            "javascript": self.tokenize_javascript,
            ".js": self.tokenize_javascript,
            ".h": self.tokenize_cpp,
            "changelog": self.tokenize_plain_text,
            "readme": self.tokenize_plain_text,
            "license": self.tokenize_plain_text,
            "copy": self.tokenize_plain_text,
            "copying": self.tokenize_plain_text,
            "copyright": self.tokenize_plain_text,
            ".jsx": self.tokenize_javascript,
            ".conf": self.tokenize_ini,
            ".properties": self.tokenize_ini,
            ".config": self.tokenize_ini,
            ".mdown": self.tokenize_markdown,
            ".mkd": self.tokenize_markdown,
            ".mkdn": self.tokenize_markdown,
            ".mdwn": self.tokenize_markdown,
            ".mdtxt": self.tokenize_markdown,
            ".mdtext": self.tokenize_markdown,
            ".text": self.tokenize_markdown,
            ".Rmd": self.tokenize_markdown,
            ".rmd": self.tokenize_markdown,
            ".rst": self.tokenize_markdown,
            ".rest": self.tokenize_markdown,
            ".txt": self.tokenize_markdown,
            ".textile": self.tokenize_markdown,
            ".pod": self.tokenize_markdown,
            "text/plain": self.tokenize_plain_text,
            "text": self.tokenize_plain_text,
            ".txt": self.tokenize_plain_text,
        }

    def tokenize_cpp(self, code: str) -> List[str]:
        try:
            index = Index.create()
            tu = index.parse(
                "tmp.cpp", args=["-std=c++11"], unsaved_files=[("tmp.cpp", code)]
            )
            return [token.spelling for token in tu.get_tokens()]
        except Exception as e:
            self.logger.error(f"Error tokenizing C++ code: {str(e)}")
            return self.tokenize_plain_text(code)

    def tokenize_xml(self, code: str) -> List[str]:
        try:
            return [elem.tag for elem in XML(code)]
        except Exception as e:
            self.logger.error(f"Error tokenizing XML code: {str(e)}")
            return self.tokenize_plain_text(code)

    def tokenize_css(self, code: str) -> List[str]:
        try:
            lexer = get_lexer_by_name("css", stripall=True)
            return [token[1] for token in lex(code, lexer)]
        except Exception as e:
            self.logger.error(f"Error tokenizing CSS code: {str(e)}")
            return self.fallback_tokenize(code)

    def tokenize_sql(self, code: str) -> List[str]:
        try:
            return [token.value for token in sql_parse(code)]
        except Exception as e:
            self.logger.error(f"Error tokenizing SQL code: {str(e)}")
            return self.tokenize_plain_text(code)

    def tokenize_yaml(self, code: str) -> List[str]:
        try:
            return [key for key in safe_load(code)]
        except Exception as e:
            self.logger.error(f"Error tokenizing YAML code: {str(e)}")
            return self.tokenize_plain_text(code)

    def tokenize_ini(self, code: str) -> List[str]:
        try:
            parser = ConfigParser()
            parser.read_string(code)
            return [section for section in parser.sections()]
        except Exception as e:
            self.logger.error(f"Error tokenizing INI code: {str(e)}")
            return self.tokenize_plain_text(code)

    def tokenize_markdown(self, code: str) -> List[str]:
        try:
            return [token for token in markdown(code)]
        except Exception as e:
            self.logger.error(f"Error tokenizing Markdown code: {str(e)}")
            return self.tokenize_plain_text(code)

    def tokenize_c(self, code: str) -> List[str]:
        try:
            parser = c_parser.CParser()
            return [token for _, token in parser.parse(code).children()]
        except Exception as e:
            self.logger.error(f"Error tokenizing C code: {str(e)}")
            return self.tokenize_plain_text(code)

    def tokenize_php(self, code: str) -> List[str]:
        try:
            return [token.value for token in src_to_tokens(code, "php")]
        except Exception as e:
            self.logger.error(f"Error tokenizing PHP code: {str(e)}")
            return self.tokenize_plain_text(code)

    def tokenize_java(self, code: str) -> List[str]:
        try:
            return [token.value for token in java_tokenize(code)]
        except Exception as e:
            self.logger.error(f"Error tokenizing Java code: {str(e)}")
            return self.tokenize_plain_text(code)

    def tokenize_javascript(self, code: str) -> List[str]:
        try:
            lexer = get_lexer_by_name("javascript", stripall=True)
            return [token[1] for token in lex(code, lexer)]
        except Exception as e:
            self.logger.error(f"Error tokenizing JavaScript code: {str(e)}")
            return self.fallback_tokenize(code)

    def tokenize_plain_text(self, code: str) -> List[str]:
        return re.findall(r"\w+|[^\w\s]", code)

    def get_pygments_lexer(self, file_type: str, code: str):
        try:
            return get_lexer_by_name(file_type, stripall=True)
        except ClassNotFound:
            try:
                return get_lexer_for_mimetype(file_type, stripall=True)
            except ClassNotFound:
                self.logger.warning(
                    f"Could not find lexer for {file_type}, guessing lexer."
                )
                return guess_lexer(code)

    def tokenize_code(self, code: str, file_type: str) -> List[str]:
        self.logger.info(f"Tokenizing code of type: {file_type}")
        try:
            if file_type in self.tokenizers:
                return self.tokenizers[file_type](code)
            else:
                lexer = self.get_pygments_lexer(file_type, code)
                return [token[1] for token in lex(code, lexer)]
        except Exception as e:
            self.logger.error(f"Error tokenizing code of type {file_type}: {str(e)}")
            self.logger.error(f"First 100 characters of problematic code: {code[:100]}")
            return self.fallback_tokenize(code)

    def subtokenize(self, tokens: List[str]) -> List[str]:
        subtokens = []
        for token in tokens:
            subtokens.extend(
                re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\W|$)|\d+", token)
            )
        return [subtoken.lower() for subtoken in subtokens if subtoken]

    def process_file_changes(
        self, file_changes: Dict[str, Dict[str, List[str]]]
    ) -> Dict[str, Dict[str, List[List[str]]]]:
        tokenized_changes = {}
        for file_path, changes in file_changes.items():
            try:
                file_type = determine_file_type(file_path, changes)
                tokenized_changes[file_path] = {
                    "added_lines": [
                        self.subtokenize(self.tokenize_code(line, file_type))
                        for line in changes.get("added_lines", [])
                    ],
                    "removed_lines": [
                        self.subtokenize(self.tokenize_code(line, file_type))
                        for line in changes.get("removed_lines", [])
                    ],
                }
            except Exception as e:
                self.logger.error(f"Error processing changes for {file_path}: {str(e)}")
                # Use a simple tokenization as fallback
                tokenized_changes[file_path] = {
                    "added_lines": [
                        self.tokenize_plain_text(line)
                        for line in changes.get("added_lines", [])
                    ],
                    "removed_lines": [
                        self.tokenize_plain_text(line)
                        for line in changes.get("removed_lines", [])
                    ],
                }
        return tokenized_changes

    def tokenize_commit(self, commit_data: Dict) -> Dict:
        tokenized_commit = commit_data.copy()
        tokenized_commit["file_changes"] = self.process_file_changes(
            commit_data["file_changes"]
        )
        return tokenized_commit

    def tokenize_file(self, input_path: str, output_path: str):
        self.logger.info(f"Tokenizing file: {input_path}")
        try:
            with open(input_path, "r") as f:
                commit_data = json.load(f)

            tokenized_data = self.tokenize_commit(commit_data)

            with open(output_path, "w") as f:
                json.dump(tokenized_data, f, indent=2)

            self.logger.info(f"Tokenized and saved: {output_path}")
        except json.JSONDecodeError as e:
            self.logger.error(f"Error decoding JSON in file {input_path}: {str(e)}")
        except IOError as e:
            self.logger.error(f"IO error while processing file {input_path}: {str(e)}")
        except Exception as e:
            self.logger.error(
                f"Unexpected error processing file {input_path}: {str(e)}"
            )

    def tokenize_directory(self, input_dir: str, output_dir: str):
        self.logger.info(f"Tokenizing directory: {input_dir}")
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                if file.endswith(".json"):
                    input_path = os.path.join(root, file)
                    relative_path = os.path.relpath(input_path, input_dir)
                    output_path = os.path.join(output_dir, relative_path)

                    os.makedirs(os.path.dirname(output_path), exist_ok=True)

                    self.tokenize_file(input_path, output_path)


def tokenize_file(input_path: str, output_path: str):
    tokenizer = CodeTokenizer()
    tokenizer.tokenize_file(input_path, output_path)


def tokenize_directory(input_dir: str, output_dir: str):
    tokenizer = CodeTokenizer()
    tokenizer.tokenize_directory(input_dir, output_dir)
