#!/usr/bin/env python3
from pathlib import Path
import re
import subprocess


PUBLIC_URL = "https://frida.re"
BUCKET_URI = "s3://frida.re"
MAX_PURGES_PER_REQUEST = 30

UPLOAD_PATTERN = re.compile(r"^upload: .+ to (s3:\/\/\S+)", re.MULTILINE)
DELETE_PATTERN = re.compile(r"^delete: (s3:\/\/\S+)", re.MULTILINE)


def main():
    repo_path = Path(__file__).parent.parent

    changes = subprocess.run(
        [
            "aws",
            "s3",
            "sync",
            "--delete",
            "--output=json",
            repo_path / "_site",
            BUCKET_URI + "/",
        ],
        capture_output=True,
        encoding="utf-8",
        check=True,
    ).stdout

    urls_to_purge = []
    for m in re.finditer(UPLOAD_PATTERN, changes):
        urls_to_purge += compute_urls_for_bucket_uri(m.group(1))
    for m in re.finditer(DELETE_PATTERN, changes):
        urls_to_purge += compute_urls_for_bucket_uri(m.group(1))

    for batch in chop(urls_to_purge, MAX_PURGES_PER_REQUEST):
        subprocess.run(["cfcli", "purge"] + batch, check=True)


def compute_urls_for_bucket_uri(uri):
    path = uri[len(BUCKET_URI):]
    result = [PUBLIC_URL + path]

    if path.endswith("/index.html"):
        slash_index = path.rindex("/")
        result += [
            PUBLIC_URL + path[:slash_index],
            PUBLIC_URL + path[:slash_index + 1]
        ]

    return result


def chop(items, n):
    for i in range(0, len(items), n):
        yield items[i:i + n]


main()
