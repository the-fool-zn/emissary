import re

IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.I)
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|xyz|top|biz|cc|tk)\b", re.I)
HASH = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)


def extract_iocs(text: str) -> dict:
    """Pull indicators of compromise out of free text. Domain matching uses a short
    TLD list on purpose (fewer false positives such as file names); extend as needed."""
    return {
        "ips": sorted(set(IP.findall(text))),
        "urls": sorted(set(URL.findall(text))),
        "domains": sorted({d.lower() for d in DOMAIN.findall(text)}),
        "hashes": sorted({h.lower() for h in HASH.findall(text)}),
    }
