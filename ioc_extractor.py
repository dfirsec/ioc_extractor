"""Extract IOCs from specific file types."""

import ipaddress
import json
import sys
from pathlib import Path

import chardet
from rich.pretty import pprint
from utils.console import console
from utils.logger import logger
from utils.regex_helper import RegexHelper

log = logger()


def get_files(source: str, extensions: tuple) -> list:
    """Returns a list of all files in a given directory with specific extensions.

    Args:
        source (str): Path where the files are located.
        extensions (tuple): Extensions to look for.

    Returns:
        A list of file paths that match the extensions in the specified source directory.
    """
    all_files = []
    for ext in extensions:
        all_files.extend(Path(source).glob(ext))
    return all_files


def process_line(regex: RegexHelper, line: str, patterns: dict) -> dict[str, list]:
    """Processes a given line of text using `regex` and returns a dictionary of patterns found in the line.

    Args:
        regex (RegexHelper): Methods for working with the `regex` patterns.
            (e.g. IP addresses, email addresses, etc.)
        line (str): The text to be processed for patterns
        patterns (dict): Dictionary that stores the patterns found.

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


def process_file(regex: RegexHelper, filename: str, patterns: dict) -> tuple[str, dict]:
    """Reads a file, detects its encoding, and processes each line using `process_line` function.

    Args:
        regex (RegexHelper): Methods for working with the `regex` patterns.
        filename (str): The name of the file to be processed
        patterns (dict): A dictionary containing `regex` patterns.

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
    """Saves a dictionary object to a file in JSON format.

    Args:
        data (dict): Data that needs to be saved to a file.
        output_file (str): Path and name where the data will be saved.
    """
    with open(output_file, "w", encoding="utf-8") as fileobj:
        json.dump(data, fileobj, indent=4)


def main(source: str, extensions: tuple) -> dict[str, dict]:
    """Main function that processes the files.

    Args:
        source (str): Directory path where the files are located.
        extensions (tuple): File extensions to look for.

    Returns:
        A dictionary containing the patterns found in the input files,
        organized by their type (e.g. "IPV4", "EMAIL", etc.).
    """
    regex = RegexHelper()
    files = get_files(source, extensions)

    if files:
        all_patterns = {}
        try:
            for filename in files:
                print(f"Processing: {filename}")
                file_path, patterns = process_file(regex, filename, {})
                if patterns:
                    all_patterns[str(file_path)] = patterns  # Convert WindowsPath to string
        except KeyboardInterrupt:
            sys.exit("\n\nUser aborted.")
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
