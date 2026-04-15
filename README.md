# IOC Extractor

This program extracts Indicators of Compromise (IOCs) from text and document files and produces triage-friendly output. It scans the provided directory recursively, filters obvious placeholders and local-only values, and saves both structured JSON and CSV reports.

**IOCs:**

- Domains
- Emails
- IPV4 addresses
- MD5 hashes
- SHA1 hashes
- SHA256 hashes
- URLs

## Prerequisites

- Python 3.12+
- `uv`

## Installation

1. Clone the repository:

    ```text
    git clone https://github.com/dfirsec/ioc_extractor.git
    ```

2. Navigate to the project directory:

    ```text
    cd ioc_extractor
    ```

3. Create or sync the environment with `uv`:

    ```text
    uv sync
    ```

This installs the project dependencies from `pyproject.toml` and `uv.lock`.

## Usage

Run the extractor with `uv`:

```text
uv run ioc_extractor.py <Directory containing potential IOCs>
```

If you prefer, the equivalent explicit form is:

```text
uv run python ioc_extractor.py <Directory containing potential IOCs>
```

> Replace `<Directory containing potential IOCs>` with the path to the directory where the files to be scanned are located.

## Supported File Types

Text-like files:

- .cfg
- .conf
- .config
- .csv
- .htm
- .html
- .ini
- .json
- .log
- .md
- .rtf
- .txt
- .xml
- .yaml
- .yml

Document files:

- .docx
- .pptx
- .xlsx
- .pdf

## Output

When actionable IOCs are found, the program writes:

- `results.json`: Full structured output with a global summary and per-file context
- `results_summary.csv`: Deduplicated IOC summary with counts and file coverage
- `results_hits.csv`: Every retained IOC hit with file path, line number, and context
- `ioc_whitelist.txt`: User-editable allowlist file created automatically if missing

## Whitelist Format

Add one entry per line in `ioc_whitelist.txt`.

```text
# Global entry
example.com

# Type-specific entry
Domain:contoso.com
URL:https://status.contoso.com/health
Email:alerts@contoso.com
```

Plain values apply to every IOC type. `TYPE:value` entries apply only to that IOC type.

## Behavior

The extractor now:

- scans directories recursively
- parses modern Office documents (`.docx`, `.xlsx`, `.pptx`) directly from their OOXML contents
- parses PDFs when `pypdf` is installed
- normalizes common obfuscation such as `[.]` and `[@]`
- removes obvious false positives such as placeholder domains and file-name-like matches
- suppresses private, reserved, loopback, and local-only IPv4 values
- retains the first line number and context for each IOC per file

## Limitations

- Legacy Office formats such as `.doc`, `.xls`, and `.ppt` are not supported.
- PDF parsing is disabled when `pypdf` is not installed; the CLI will tell you when that is the case.
- OOXML extraction is text-focused and does not preserve document layout.

## Example

```text
uv run ioc_extractor.py "C:\Users\name\Documents\cases"
```

## License

This project is licensed under the MIT License.
