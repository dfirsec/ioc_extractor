"""Extract IOCs from specific file types."""

import ipaddress
import json
import sys
from pathlib import Path
from typing import Dict, Tuple

import chardet
from rich.pretty import pprint
from utils.console import console
from utils.logger import logger
from utils.regex_helper import RegexHelper

log = logger()


def get_files(source: str, extensions: tuple) -> list:
    """
    Returns a list of all files in a given source directory with specific extensions.

    Args:
        source (str):
          A string representing the directory path where the files are located.
        extensions (tuple):
          A tuple of file extensions that the function should look for in the
            specified source directory.

    Returns:
        A list of file paths that match the given extensions in the specified source directory.
    """
    all_files = []
    for ext in extensions:
        all_files.extend(Path(source).glob(ext))
    return all_files


def process_line(regex: RegexHelper, line: str, patterns: dict) -> Dict[str, list]:
    """
    Processes a given line of text using `regex` and returns a dictionary of patterns found in the line.

    Args:
        regex (RegexHelper):
          A helper class that contains regular expression patterns for different types of data
            (e.g. IP addresses, email addresses, etc.)
        line (str):
          The input string that contains the text to be processed for patterns
        patterns (dict):
          A dictionary that stores the patterns found in the input line.

    Returns:
        A dictionary containing the patterns found in the input line, organized by their type (e.g.
        "IPV4", "EMAIL", etc.). The dictionary is updated with any new patterns found in the input line.
    """
    for name, regex_type in regex.regex_patterns(line).items():
        for pattern in regex_type:
            if name == "IPV4":
                try:
                    ipaddress.IPv4Address(pattern)
                except ipaddress.AddressValueError:
                    continue  # Skip invalid IP addresses

            # Ensure the key exists in the dictionary
            if name not in patterns:
                patterns[name] = []

            # Add the pattern to the list only if it's not already present
            cleaned_pattern = pattern.lower().replace("[.]", ".").replace(",url,,", "")
            if cleaned_pattern not in patterns[name]:
                patterns[name].append(cleaned_pattern)

    return patterns


def process_file(regex: RegexHelper, filename: str, patterns: dict) -> Tuple[str, dict]:
    """
    Reads a file, detects its encoding, and processes each line using `process_line` function.

    Args:
        regex (RegexHelper):
          An instance of the RegexHelper class, which provides methods for working
            with `regex` patterns.
        filename (str):
          The name of the file to be processed,
        patterns (dict):
          A dictionary containing `regex` patterns as keys and their corresponding
            counts as values.

    Returns:
        A tuple containing the filename and a dictionary of patterns.
    """
    with open(filename, "rb") as fileobj:
        raw_data = fileobj.read()

    try:
        encoding = chardet.detect(raw_data)["encoding"] or "utf-8"
    except UnicodeDecodeError:
        log.error(f"Error: Cannot decode the file {filename}. Skipping this file.")
        return filename, patterns

    data = raw_data.decode(encoding)

    for line in data.splitlines():
        patterns = process_line(regex, line, patterns)

    return filename, patterns


def save_to_file(data: dict, output_file: str) -> None:
    """
    Ssaves a dictionary object to a file in JSON format.

    Args:
        data (dict):
          A dictionary containing the data that needs to be saved to a file.
        output_file (str):
          Represents the file path and name where the data will be saved.
    """
    with open(output_file, "w", encoding="utf-8") as fileobj:
        json.dump(data, fileobj, indent=4)


def main(source: str, extensions: tuple) -> Dict[str, Dict]:
    """
    Main function that processes files in a given directory and returns a dictionary of patterns found.

    Args:
        source (str):
          The directory path where the files to be processed are located.
        extensions (tuple):
            A tuple of file extensions that the function should look for in the
                specified source directory.

    Returns:
        A dictionary where the keys are the file paths of the processed files (as strings) and the values
        are dictionaries containing the patterns found in each file. If no files are found or no patterns
        are found in the files, an empty dictionary is returned.
    """
    regex = RegexHelper()
    files = get_files(source, extensions)

    if files:
        all_patterns = {}
        for filename in files:
            file_path, patterns = process_file(regex, filename, {})
            if patterns:
                all_patterns[str(file_path)] = patterns  # Convert WindowsPath to string
        return all_patterns

    return {}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: python ioc_extractor.py <Directory containing potential IOCs>")
    else:
        source = sys.argv[1]

    extensions = (
        "*.cfg",
        "*.conf",
        "*.config",
        "*.csv",
        "*.htm",
        "*.html",
        "*.ini",
        "*.json",
        "*.log",
        "*.md",
        "*.rtf",
        "*.txt",
        "*.xml",
        "*.yaml",
        "*.yml",
    )

    output = main(source, extensions)
    if Path(source).is_dir() and output:
        pprint(output)
        save_to_file(output, "results.json")
    else:
        console.print("Source must be a directory that exists and contains files with these extensions:")
        [console.print(f"  {ext.strip('*')}") for ext in extensions]
