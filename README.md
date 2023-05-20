# IOC Extractor

This program is designed to extract Indicators of Compromise (IOCs) from specific file types. It scans the provided directory for files with specified extensions and searches for patterns such as IP addresses, email addresses, and more.

**IOCs:**

- Domains
- Emails
- IPV4 addresses
- MD5 hashes
- SHA1 hashes
- SHA256 hashes
- URLs

## Prerequisites

Python 3.6+

## Installation

1. Clone the repository:

```text
git clone https://github.com/dfirsec/ioc_extractor.git
```

2. Navigate to the project directory:

```text
cd ioc_extractor
```

1. Install the required dependencies:

```text
poetry install
```

## Usage

```text
python ioc_extractor.py <Directory containing potential IOCs>
```

> Replace \<Directory containing potential IOCs> with the path to the directory where the files to be scanned are located.

## Supported File Types

The program supports the following file types:

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

## Additional Functions

The program also includes the following additional functions (see `utils/regex_helper.py`):

```python
def get_valid_tlds() -> list[str]:
    """Uses a list of top-level domains (TLDs) and returns the list of TLDs.

    Returns:
        A list of valid top-level domains (TLDs) either from a local file named "tlds.txt" or by downloading them from IANA.org if the file is not found.
    """
    ...
```

This function retrieves a list of valid top-level domains (TLDs). It first checks for a local file named "tlds.txt" and returns the list of TLDs from the file if it exists. If the file is not found, it downloads the list of TLDs from IANA.org and saves them to the file.

--

```python
def download_tlds() -> list[str]:
    """Downloads a list of valid top-level domains (TLDs) and saves them to a file.

    Returns:
        A list of valid top-level domains (TLDs).
    """
    ...
```

This function downloads the list of valid top-level domains (TLDs) from IANA.org and saves them to a file named "tlds.txt". It returns the list of downloaded TLDs.

## Output

The program will display the extracted patterns organized by their type, such as "IPV4", "EMAIL", etc.  The extracted patterns will also be saved to a JSON file named results.json in the current directory.

## Example

```text
python ioc_extractor.py "/path/to/files"
```

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvement, please create an issue or submit a pull request.

## License
This project is licensed under the MIT License.