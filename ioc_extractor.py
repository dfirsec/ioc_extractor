"""Extract and triage IOCs from supported document types."""

import argparse
import csv
import ipaddress
import json
import sys
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import TypedDict
from xml.etree import ElementTree

import chardet
from rich.pretty import pprint
from utils.console import console
from utils.logger import logger
from utils.regex_helper import RegexHelper

try:
    from pypdf import PdfReader
except ImportError:  # pragma: no cover - optional dependency in local environments
    PdfReader = None

log = logger()

BENIGN_DOMAINS = {
    "example.com",
    "example.net",
    "example.org",
    "localhost",
    "test",
    "test.local",
    "domain.com",
}

BENIGN_EMAIL_DOMAINS = {
    "example.com",
    "example.net",
    "example.org",
}

BENIGN_URL_PREFIXES = (
    "http://example.com",
    "https://example.com",
    "http://localhost",
    "https://localhost",
)

FILE_LIKE_DOMAIN_SUFFIXES = (
    ".cfg",
    ".conf",
    ".config",
    ".csv",
    ".htm",
    ".html",
    ".ini",
    ".json",
    ".log",
    ".md",
    ".pdf",
    ".pptx",
    ".rtf",
    ".txt",
    ".xml",
    ".xlsx",
    ".yaml",
    ".yml",
)

TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".config",
    ".csv",
    ".htm",
    ".html",
    ".ini",
    ".json",
    ".log",
    ".md",
    ".rtf",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

OOXML_EXTENSIONS = {".docx", ".pptx", ".xlsx"}
DEFAULT_WHITELIST_PATH = Path("ioc_whitelist.txt")
OUTPUT_JSON = "results.json"
OUTPUT_SUMMARY_CSV = "results_summary.csv"
OUTPUT_HITS_CSV = "results_hits.csv"
SUPPORTED_EXTENSIONS = (
    "*.cfg",
    "*.conf",
    "*.config",
    "*.csv",
    "*.docx",
    "*.htm",
    "*.html",
    "*.ini",
    "*.json",
    "*.log",
    "*.md",
    "*.pdf",
    "*.pptx",
    "*.rtf",
    "*.txt",
    "*.xml",
    "*.xlsx",
    "*.yaml",
    "*.yml",
)


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    supported_types = ", ".join(ext.strip("*") for ext in SUPPORTED_EXTENSIONS)
    parser = argparse.ArgumentParser(
        description=(
            "Recursively scan a directory for supported files, extract actionable IOCs, "
            "and write JSON and CSV reports."
        ),
        epilog=(
            "Supported file types: "
            f"{supported_types}\n"
            f"Outputs: {OUTPUT_JSON}, {OUTPUT_SUMMARY_CSV}, {OUTPUT_HITS_CSV}\n"
            "Whitelist: ioc_whitelist.txt is created automatically if missing and accepts "
            "plain values or TYPE:value entries."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "source",
        help="Directory containing files to scan for IOCs.",
    )
    return parser

def get_files(source: str, extensions: tuple[str, ...]) -> list[str]:
    """Return all matching files in the directory tree."""
    all_files: list[str] = []
    source_path = Path(source)
    for ext in extensions:
        all_files.extend(str(path) for path in source_path.rglob(ext) if path.is_file())
    return sorted(set(all_files))


def normalize_pattern(pattern: str) -> str:
    """Normalize extracted IOCs for consistent matching and output."""
    cleaned = pattern.lower().replace("[.]", ".").replace("[@]", "@").replace(",url,,", "")
    return cleaned.strip(" \t\r\n\"'`[]()<>{},;:")


def ensure_whitelist_file(path: Path) -> None:
    """Create a default whitelist file if one does not already exist."""
    if path.exists():
        return

    path.write_text(
        "# IOC whitelist\n"
        "# One entry per line.\n"
        "# Use either a plain value or TYPE:value.\n"
        "# Examples:\n"
        "# example.com\n"
        "# Domain:contoso.com\n"
        "# URL:https://status.contoso.com/health\n",
        encoding="utf-8",
    )


def load_whitelist(path: Path) -> dict[str, set[str]]:
    """Load global and per-type whitelist entries."""
    ensure_whitelist_file(path)
    whitelist: dict[str, set[str]] = defaultdict(set)

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" in line:
            ioc_type, value = line.split(":", 1)
            normalized_type = ioc_type.strip()
            normalized_value = normalize_pattern(value.strip())
            if normalized_type and normalized_value:
                whitelist[normalized_type].add(normalized_value)
        else:
            whitelist["*"].add(normalize_pattern(line))

    return {key: values for key, values in whitelist.items()}


def is_whitelisted(name: str, pattern: str, whitelist: dict[str, set[str]]) -> bool:
    """Return True when the IOC is explicitly whitelisted."""
    return pattern in whitelist.get("*", set()) or pattern in whitelist.get(name, set())


def is_actionable_ioc(name: str, pattern: str, whitelist: dict[str, set[str]]) -> bool:
    """Filter obvious placeholders, private infrastructure, and whitelisted values."""
    if not pattern:
        return False

    if is_whitelisted(name, pattern, whitelist):
        return False

    if "/" in pattern or "\\" in pattern:
        return False

    if name == "IPV4":
        try:
            address = ipaddress.IPv4Address(pattern)
        except ipaddress.AddressValueError:
            return False
        return not (
            address.is_private
            or address.is_loopback
            or address.is_multicast
            or address.is_reserved
            or address.is_link_local
            or address.is_unspecified
        )

    if name == "Domain":
        if pattern.endswith(FILE_LIKE_DOMAIN_SUFFIXES):
            return False
        return not (pattern in BENIGN_DOMAINS or pattern.endswith(".example.com") or ".local" in pattern)

    if name == "Email":
        domain = pattern.split("@")[-1]
        return not (domain in BENIGN_EMAIL_DOMAINS or domain.endswith(".example.com") or ".local" in domain)

    if name == "URL":
        return not (
            any(pattern.startswith(prefix) for prefix in BENIGN_URL_PREFIXES)
            or "example.com" in pattern
            or "localhost" in pattern
        )

    return True


def record_match(patterns: dict[str, list[dict]], name: str, value: str, line: str, line_number: int) -> None:
    """Store a unique IOC match together with its source context."""
    if name not in patterns:
        patterns[name] = []

    if any(entry["value"] == value for entry in patterns[name]):
        return

    patterns[name].append({
        "value": value,
        "line_number": line_number,
        "context": line.strip(),
    })


def process_line(
    regex: RegexHelper,
    line: str,
    line_number: int,
    patterns: dict[str, list[dict]],
    whitelist: dict[str, set[str]],
) -> dict[str, list[dict]]:
    """Extract actionable IOCs from a line and retain first-seen context."""
    for name, regex_type in regex.regex_patterns(line).items():
        for pattern in regex_type:
            cleaned_pattern = normalize_pattern(pattern)
            if is_actionable_ioc(name, cleaned_pattern, whitelist):
                record_match(patterns, name, cleaned_pattern, line, line_number)

    return patterns


def decode_text_file(filename: str) -> str:
    """Read a text-like file using charset detection with a latin-1 fallback."""
    with Path(filename).open("rb") as fileobj:
        raw_data = fileobj.read()

    try:
        encoding = chardet.detect(raw_data)["encoding"] or "utf-8"
        return raw_data.decode(encoding)
    except UnicodeDecodeError:
        try:
            return raw_data.decode("ISO-8859-1")
        except UnicodeDecodeError as exc:
            raise ValueError("Cannot decode file") from exc


def extract_xml_text(xml_content: bytes) -> list[str]:
    """Extract visible text nodes from XML-like content."""
    try:
        root = ElementTree.fromstring(xml_content)
    except ElementTree.ParseError:
        return []

    lines = [text.strip() for text in root.itertext() if text and text.strip()]
    return lines


def extract_ooxml_lines(filename: str) -> list[str]:
    """Extract text from OOXML containers such as DOCX, PPTX, and XLSX."""
    suffix = Path(filename).suffix.lower()
    prefixes = {
        ".docx": ("word/",),
        ".pptx": ("ppt/slides/", "ppt/notesSlides/"),
        ".xlsx": ("xl/sharedStrings.xml", "xl/worksheets/"),
    }
    lines: list[str] = []

    with zipfile.ZipFile(filename) as archive:
        for member in sorted(archive.namelist()):
            if member.endswith("/"):
                continue
            if not member.endswith(".xml"):
                continue
            if not any(member == prefix or member.startswith(prefix) for prefix in prefixes[suffix]):
                continue
            lines.extend(extract_xml_text(archive.read(member)))

    return lines


def extract_pdf_lines(filename: str) -> list[str]:
    """Extract text from PDF pages when pypdf is available."""
    if PdfReader is None:
        log.warning("Skipping PDF parsing for %s because pypdf is not installed.", filename)
        return []

    lines: list[str] = []
    reader = PdfReader(filename)
    for page_number, page in enumerate(reader.pages, start=1):
        page_text = page.extract_text() or ""
        for line in page_text.splitlines():
            stripped = line.strip()
            if stripped:
                lines.append(f"[page {page_number}] {stripped}")
    return lines


def extract_lines(filename: str) -> list[str]:
    """Extract text lines from supported file types."""
    suffix = Path(filename).suffix.lower()

    if suffix in TEXT_EXTENSIONS:
        return decode_text_file(filename).splitlines()

    if suffix in OOXML_EXTENSIONS:
        return extract_ooxml_lines(filename)

    if suffix == ".pdf":
        return extract_pdf_lines(filename)

    return []


def process_file(
    regex: RegexHelper,
    filename: str,
    patterns: dict[str, list[dict]],
    whitelist: dict[str, set[str]],
) -> tuple[str, dict[str, list[dict]]]:
    """Read a supported file and extract IOCs with context."""
    try:
        lines = extract_lines(filename)
    except (ValueError, zipfile.BadZipFile, OSError) as exc:
        log.exception("Error processing file %s. Skipping this file. Reason: %s", filename, exc)
        return filename, patterns

    for line_number, line in enumerate(lines, start=1):
        patterns = process_line(regex, line, line_number, patterns, whitelist)

    return filename, patterns


class SummaryItem(TypedDict):
    value: str
    count: int
    files: list[str]


class SummaryPayload(TypedDict):
    count: int
    items: list[SummaryItem]


def build_summary(file_results: dict[str, dict[str, list[dict]]]) -> dict[str, SummaryPayload]:
    """Build a global summary grouped by IOC type with counts and file coverage."""
    summary: dict[str, dict[str, SummaryItem]] = defaultdict(dict)

    for file_path, patterns in file_results.items():
        for ioc_type, matches in patterns.items():
            for match in matches:
                value = match["value"]
                if value not in summary[ioc_type]:
                    summary[ioc_type][value] = {
                        "value": value,
                        "count": 0,
                        "files": [],
                    }
                summary_entry = summary[ioc_type][value]
                summary_entry["count"] += 1
                if file_path not in summary_entry["files"]:
                    summary_entry["files"].append(file_path)

    return {
        ioc_type: {
            "count": len(entries),
            "items": sorted(entries.values(), key=lambda item: (-item["count"], item["value"])),
        }
        for ioc_type, entries in sorted(summary.items())
    }


def save_to_file(data: dict, output_file: str) -> None:
    """Save extracted data to a JSON file."""
    with Path(output_file).open("w", encoding="utf-8") as fileobj:
        json.dump(data, fileobj, indent=4)


def save_summary_csv(summary: dict[str, SummaryPayload], output_file: str) -> None:
    """Save the deduplicated IOC summary to CSV."""
    with Path(output_file).open("w", encoding="utf-8", newline="") as fileobj:
        writer = csv.writer(fileobj)
        writer.writerow(["ioc_type", "value", "count", "file_count", "files"])
        for ioc_type, payload in summary.items():
            for item in payload["items"]:
                writer.writerow([
                    ioc_type,
                    item["value"],
                    item["count"],
                    len(item["files"]),
                    "; ".join(item["files"]),
                ])


def save_hits_csv(file_results: dict[str, dict[str, list[dict]]], output_file: str) -> None:
    """Save every retained IOC hit with file and line context to CSV."""
    with Path(output_file).open("w", encoding="utf-8", newline="") as fileobj:
        writer = csv.writer(fileobj)
        writer.writerow(["file", "ioc_type", "value", "line_number", "context"])
        for file_path, patterns in sorted(file_results.items()):
            for ioc_type, matches in sorted(patterns.items()):
                for match in matches:
                    writer.writerow([
                        file_path,
                        ioc_type,
                        match["value"],
                        match["line_number"],
                        match["context"],
                    ])


def main(source: str, extensions: tuple[str, ...], whitelist_path: Path = DEFAULT_WHITELIST_PATH) -> dict[str, dict]:
    """Process files and return a triage-friendly IOC report."""
    regex = RegexHelper()
    whitelist = load_whitelist(whitelist_path)
    if files := get_files(source, extensions):
        file_results: dict[str, dict[str, list[dict]]] = {}
        try:
            for filename in files:
                print(f"Processing: {filename}")
                file_path, patterns = process_file(regex, filename, {}, whitelist)
                if patterns:
                    file_results[str(file_path)] = patterns
        except KeyboardInterrupt:
            sys.exit("\n\nUser aborted.")

        if not file_results:
            return {}

        return {
            "summary": build_summary(file_results),
            "files": file_results,
        }

    return {}


if __name__ == "__main__":
    parser = build_argument_parser()
    args = parser.parse_args()
    source = args.source

    output = main(source, SUPPORTED_EXTENSIONS)
    if not Path(source).is_dir():
        console.print("[bold red]Source must be an existing directory.[/bold red]")
        console.print("Supported file types:")
        for ext in SUPPORTED_EXTENSIONS:
            console.print(f"  {ext.strip('*')}")
        sys.exit(2)
    elif output:
        pprint(output)
        save_to_file(output, OUTPUT_JSON)
        save_summary_csv(output["summary"], OUTPUT_SUMMARY_CSV)
        save_hits_csv(output["files"], OUTPUT_HITS_CSV)
        console.print(
            f"Saved [bold]{OUTPUT_JSON}[/bold], [bold]{OUTPUT_SUMMARY_CSV}[/bold], and [bold]{OUTPUT_HITS_CSV}[/bold]."
        )
        console.print(f"Whitelist file: [bold]{DEFAULT_WHITELIST_PATH}[/bold]")
        if PdfReader is None:
            console.print("PDF support is disabled until `pypdf` is installed.")
    else:
        console.print(
            "No actionable IOCs found in the scanned files after filtering placeholders, local-only values, and whitelist entries."
        )
        console.print(f"Whitelist file: [bold]{DEFAULT_WHITELIST_PATH}[/bold]")
        if PdfReader is None:
            console.print("PDF support is disabled until `pypdf` is installed.")

