#!/usr/bin/env python3
import os
import subprocess


PUBLIC_URL = "https://frida.re"
BUCKET_URI = "s3://frida.re"
MAX_PURGES_PER_REQUEST = 30


def main():
    repo_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    urls = []
    listing = subprocess.check_output([
        "s3cmd",
        "ls",
        "-r",
        BUCKET_URI
    ]).decode('utf-8')
    lines = listing.rstrip().split("\n")
    for line in lines:
        path = line[line.index(BUCKET_URI) + len(BUCKET_URI):]
        urls += compute_urls_for_path(path)

    subprocess.check_call([
        "s3cmd",
        "sync",
        "--delete-removed",
        os.path.join(repo_path, "_site") + os.sep,
        BUCKET_URI + "/"
    ])

    for batch in chop(urls, MAX_PURGES_PER_REQUEST):
        subprocess.check_call(["cfcli", "purge"] + batch)


def compute_urls_for_path(path):
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
