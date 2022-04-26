"""Extract IOCs from txt, csv, or xml files."""

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.0.1"
__description__ = "IOC Extractor"

import json
import re
import sys
from pathlib import Path


class RegexHelper:
    @staticmethod
    def regex(_type):
        pattern = dict(
            domain=r"([a-za-z0-9]+(?:[\-|\.|][a-za-z0-9]+)*(?<!fireeye)(?<!mitre)(?<!lockheedmartin)(?<!w3)"
            r"(?:\[\.\]|\.)(?![a-z-]*.\.gov|gen|gov|add|ad|ako|area|argv|asn|asp|bar|bat|bak|bin|bmp|btz"
            r"|cfg|cfm|class|cpj|conf|copy|css|dat|db|dldr|dll|dis|dns|doc|div|drv|dx|err|exe|file|foo|get"
            r"|gif|gov|gz|hta|htm|http|img|inf|ini|jar|java|jsp|jpg|js|key|lnk|log|md|min|msi|mtx|mul|nat"
            r"|name|rar|rer|rpm|rss|ocx|out|pack|pcap|pdf|php|pop|png|ps|put|py|src|sh|sort|sys|tmp|txt|user"
            r"|vbe|vbs|xls|xml|xpm|xsd|zip|[i\.e]$|[e\.g]$)(?:[a-z]{2,4})\b|(?:\[\.\][a-z]{2,4})(?!@)$)",
            email=r"([a-za-z0-9_.+-]+(\[@\]|@)(?!fireeye)[a-za-z0-9-.]+(\.|\[\.\])(?![a-z-]+\.gov|gov)([a-za-z0-9-.]{"
            r"2,6}\b))",
            ipv4=r"(((?![0])(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\[\.\]|\.))){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]["
            r"0-9]?)",
            md5=r"\b[a-fa-f0-9]{32}\b",
            sha1=r"\b[a-fa-f0-9]{40}\b",
            sha256=r"\b[a-fa-f0-9]{64}\b",
            url=r"((http|hxxp)[s]?:\/\/(?!.+\.gov|gov)(?!.+fireeye)(?!.+mitre)(?!.+lockheedmartin)(?!.+w3)"
            r"(?:[a-za-z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:[0-9a-fa-f][0-9a-fa-f]))(?:[^,;\"])+(?<![\s\W]))",
        )
        return re.compile(pattern[_type])

    @staticmethod
    def regex_iter(regex, text):
        return [x.group() for x in re.finditer(regex, text.lower())]

    def regex_patterns(self, text):
        return {
            "Domain": self.regex_iter(self.regex(_type="domain"), text),
            "Email": self.regex_iter(self.regex(_type="email"), text),
            "IPV4": self.regex_iter(self.regex(_type="ipv4"), text),
            "MD5": self.regex_iter(self.regex(_type="md5"), text),
            "SHA1": self.regex_iter(self.regex(_type="sha1"), text),
            "SHA256": self.regex_iter(self.regex(_type="sha256"), text),
            "URL": self.regex_iter(self.regex(_type="url"), text),
        }


def get_files(source, extensions):
    all_files = []
    for ext in extensions:
        all_files.extend(Path(source).glob(ext))
    return all_files


def add_values_in_dict(data_dict, key, values):
    if key not in data_dict:
        data_dict[key] = []
    data_dict[key].extend(values)
    return data_dict


def main(source):
    regex = RegexHelper()
    files = get_files(source, ("*.txt", "*.csv", "*.xml"))
    data = {}

    if files:
        for filename in files:
            with open(filename, encoding="utf-8") as fileobj:
                for line in fileobj:
                    for name, regex_type in regex.regex_patterns(line).items():
                        for pattern in regex_type:
                            add_values_in_dict(data, name, [pattern.lower().replace("[.]", ".").replace(",url,,", "")])
    else:
        sys.exit("[!] Doesn't appear to be any files that exist with .txt, .csv, or .xml extensions.")

    dictnew = {a: list(set(b)) for a, b in data.items()}
    jsonobj = json.dumps(dictnew, indent=4)
    root = Path(__file__).resolve().parent
    results = root.joinpath("results.json")

    if jsonobj and dictnew:
        data = json.loads(jsonobj)
        for key in data:
            print(f"\n{key} Count: {len(data[key])}\n==================")
            for value in data[key]:
                print(value)

        with open(results, "w", encoding="utf-8") as outfile:
            json.dump(dictnew, outfile, indent=4)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: python ioc_extractor.py <Directory containing IOCs>")
    else:
        arg = sys.argv[1]
    main(arg)
