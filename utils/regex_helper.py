"""Desc: Helper class for regular expressions."""
import re
from pathlib import Path

import requests
from utils.console import console
from utils.logger import logger


def get_valid_tlds() -> list[str]:
    """Uses a list of top-level domains (TLDs) and returns the list of TLDs.

    Returns:
        A list of valid top-level domains (TLDs) either from a local file named "tlds.txt" or by
        downloading them from a remote source if the file is not found.
    """
    try:
        with open(Path(__file__).resolve().parent / "tlds.txt") as fileobj:
            return [line.strip() for line in fileobj]
    except FileNotFoundError:
        return download_tlds()


def download_tlds() -> list[str]:
    """Downloads a list of valid top-level domains (TLDs) and saves them to a file.

    Returns:
        A list of valid top-level domains (TLDs) that have been downloaded and
        written to a file specified by the `filename` parameter.
    """
    log = logger()
    console.print("[blue][!] The TLD file is missing, downloading file...\n")
    try:
        response = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        log.error(f"Error downloading file: {err}")
        return []
    tlds = response.text.strip().split("\n")
    valid_tlds = [tld.lower() for tld in tlds]

    with open(Path(__file__).resolve().parent / "tlds.txt", "w") as fileobj:
        fileobj.write("\n".join(valid_tlds))
    return valid_tlds


class RegexHelper:
    """Helper class for regular expressions."""

    def __init__(self):
        """Load valid TLDs from file."""
        self.tlds = get_valid_tlds()

    def regex(self, retype: str) -> re.Pattern:
        """Returns a compiled regular expression pattern based on the input type.

        Args:
            retype (str):
              A string indicating the type of regular expression pattern to be compiled. It can
                be one of the following: "domain", "url", "email", "ipv4", "md5", "sha1", or "sha256".

        Returns:
            re.Pattern:
              Returns a compiled regular expression pattern based on the input `retype`
        """
        tld_pattern = "|".join(map(re.escape, self.tlds))

        pattern = {
            "domain": (
                r"([A-Za-z0-9]+(?:[\-|\.|][A-Za-z0-9]+)*(?:\[\.\]|\.)(?![a-z-]*.[i\.e]$|[e\.g]$)"
                rf"(?:{tld_pattern})\b|(?:\[\.\][a-z]{2,4})(?!@)$)"
            ),
            "url": (
                r"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}"
                r"\b([-a-zA-Z0-9@:%_\+.~#?&\/\/=\*]*))"
            ),
            "email": (r"([a-za-z0-9_.+-]+(\[@\]|@)[a-za-z0-9-.]+(\.|\[\.\])(?![a-z-]+\.)[a-za-z0-9-.]{2,6}\b)"),
            "ipv4": (
                r"(((?![0])(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:[.]|(?:[\[]{1}[.][\]]{1})))){3}"
                r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
            ),
            "md5": (r"\b[a-fA-F0-9]{32}\b"),
            "sha1": (r"\b[a-fA-F0-9]{40}\b"),
            "sha256": (r"\b[a-fA-F0-9]{64}\b"),
        }
        return re.compile(pattern[retype], re.IGNORECASE)

    def regex_iter(self, regex: re.Pattern, text: str) -> list[str]:
        """Returns a list of all non-overlapping matches of the regular expression in the string.

        Args:
            regex (re.Pattern):
              A compiled `regex` pattern that will be used to search for matches in the given text.
            text (str):
              The input string on which the `regex` pattern will be applied.

        Returns:
            Returns a list of strings that match the given `regex` in the given `text`.
        """
        return [re.group() for re in re.finditer(regex, text.lower())]

    def regex_patterns(self, text: str) -> dict:
        """Returns a dictionary containing regex patterns for domain, email, IPV4, MD5, SHA1, SHA256, and URL.

        Args:
            text (str):
              The input text on which the regular expressions will be applied to extract specific
                patterns.

        Returns:
            A dictionary containing regex matches for the various patterns.
        """
        return {
            "Domain": self.regex_iter(self.regex(retype="domain"), text),
            "Email": self.regex_iter(self.regex(retype="email"), text),
            "IPV4": self.regex_iter(self.regex(retype="ipv4"), text),
            "MD5": self.regex_iter(self.regex(retype="md5"), text),
            "SHA1": self.regex_iter(self.regex(retype="sha1"), text),
            "SHA256": self.regex_iter(self.regex(retype="sha256"), text),
            "URL": self.regex_iter(self.regex(retype="url"), text),
        }
