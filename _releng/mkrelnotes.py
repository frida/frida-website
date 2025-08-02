#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import requests
import semver
from openai import OpenAI


@dataclass
class Commit:
    summary: str
    full_text: str
    author: Author


@dataclass
class Author:
    name: str
    email: str


def main():
    repo_root = Path(__file__).resolve().parent.parent
    posts_dir = repo_root / "_i18n" / "en" / "_posts"
    frida_repo = Path(sys.argv[1])
    tag = sys.argv[2]

    summary = extract_release_metadata(frida_repo, tag)
    example_note = (posts_dir / "2024-10-14-frida-16-5-6.markdown").read_text(
        encoding="utf-8"
    )
    notes = generate_release_notes(summary, example_note, OpenAI())

    short_date = summary["date"].split(" ")[0]
    dashed_tag = tag.replace(".", "-")
    post_file = posts_dir / f"{short_date}-frida-{dashed_tag}-released.markdown"
    post_file.write_text(notes, encoding="utf-8")


def generate_release_notes(summary: dict, example_note: str, client) -> str:
    prompt = "\n".join(
        [
            (
                "You are the maintainer of an open source project called Frida. "
                "One of your earlier release notes looked like this:"
            ),
            "```",
            example_note,
            "```",
            (
                "Generate release notes for this new release. "
                "Wrap lines at 80 columns. "
                "Only include credit when the author's name isn't `Ole Andr\u00e9 Vadla Ravn\u00e5s`. "
                "If the release date is on the same day as the previous release, include a witty remark"
                "about software being hard."
            ),
            "```json",
            json.dumps(summary),
            "```",
        ]
    )
    completion = client.chat.completions.create(
        model="o3",
        messages=[
            {
                "role": "user",
                "content": prompt,
            },
        ],
    )
    return completion.choices[0].message.content


def extract_release_metadata(repo: Path, tag: str) -> dict:
    previous_tag = get_previous_tag(repo, tag)
    version = tag
    date = get_tag_date(repo, tag)
    previous_date = get_tag_date(repo, previous_tag)

    commit_messages = get_git_log(repo, previous_tag, tag)
    commit_messages += get_submodule_commits(repo, previous_tag, tag)
    commit_messages = filter_commit_messages(commit_messages)

    return {
        "tag": version,
        "date": date,
        "commit_messages": [
            {
                "summary": commit.summary,
                "full_text": commit.full_text,
                "author": {"name": commit.author.name, "email": commit.author.email},
            }
            for commit in commit_messages
        ],
        "previous_release": {"tag": previous_tag, "date": previous_date},
    }


def get_previous_tag(repo: Path, current_tag: str) -> str:
    cmd = ["git", "tag", "--sort=-v:refname"]
    result = subprocess.run(cmd, cwd=repo, capture_output=True, text=True)
    tags = result.stdout.split("\n")
    current_version = semver.VersionInfo.parse(current_tag)

    for tag in tags:
        try:
            version = semver.VersionInfo.parse(tag)
            if version < current_version:
                return tag
        except ValueError:
            continue
    raise ValueError(f"No previous tag found for {current_tag}")


def get_tag_date(repo: Path, tag: str) -> str:
    cmd = ["git", "show", "-s", "--format=%ci", tag]
    result = subprocess.run(cmd, cwd=repo, capture_output=True, text=True)
    return result.stdout.strip()


def get_git_log(repo_path: Path, from_commit: str, to_commit: str) -> list[Commit]:
    delimiter = "===END==="
    cmd = [
        "git",
        "log",
        f"{from_commit}..{to_commit}",
        f"--pretty=format:%an <%ae>%n%s%n%b{delimiter}",
    ]
    result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True)
    raw_commits = result.stdout.split(delimiter)
    commits = []
    for raw_commit in raw_commits:
        if raw_commit.strip():
            parts = raw_commit.lstrip().split("\n", 2)
            author_info = parts[0]
            summary = parts[1]
            full_text = parts[2].rstrip() if len(parts) > 2 else ""

            author_name, author_email = author_info.rsplit(" <", 1)
            author_email = author_email.rstrip(">")
            author = Author(name=author_name, email=author_email)

            commits.append(Commit(summary=summary, full_text=full_text, author=author))
    return commits


def fetch_commits_from_github(
    repo_name: str, old_commit: str, new_commit: str
) -> list[Commit]:
    token = os.environ["GH_TOKEN"]

    url = f"https://api.github.com/repos/frida/{repo_name}/compare/{old_commit}...{new_commit}"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Accept": "application/vnd.github.v3+json",
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()

    commits = []
    for commit_data in data["commits"]:
        author_name = commit_data["commit"]["author"]["name"]
        author_email = commit_data["commit"]["author"]["email"]
        summary = commit_data["commit"]["message"].split("\n")[0]
        full_text = commit_data["commit"]["message"]

        author = Author(name=author_name, email=author_email)
        commits.append(Commit(summary=summary, full_text=full_text, author=author))

    return commits


def get_submodule_commits(repo: Path, tag1: str, tag2: str) -> list[Commit]:
    cmd = ["git", "diff", "--submodule", tag1, tag2]
    result = subprocess.run(cmd, cwd=repo, capture_output=True, text=True)
    submodule_changes = result.stdout.split("\n")

    submodule_commits = []
    for line in submodule_changes:
        if line.startswith("Submodule"):
            parts = line.split(" ")

            submodule_path = parts[1]
            submodule_repo = repo / submodule_path
            if submodule_repo.name in {"capstone", "frida-tools", "meson", "udis86"}:
                continue

            raw_commit_range = parts[2][:-1]
            commit_range = raw_commit_range.split("...")
            if len(commit_range) != 2:
                commit_range = raw_commit_range.split("..")
            old_commit = commit_range[0]
            new_commit = commit_range[1]
            if old_commit == "0000000" or new_commit == "000000":
                continue

            if (
                submodule_repo.name != "releng"
                and submodule_repo.parent.name != "subprojects"
            ):
                submodule_repo = repo / "subprojects" / submodule_repo.name
                if not submodule_repo.exists():
                    submodule_commits.extend(
                        fetch_commits_from_github(
                            submodule_repo.name, old_commit, new_commit
                        )
                    )
                    continue

            submodule_commits.extend(
                get_git_log(submodule_repo, old_commit, new_commit)
            )
    return submodule_commits


def filter_commit_messages(commit_messages: list[Commit]) -> list[Commit]:
    filtered_messages = []
    for commit in commit_messages:
        if commit.summary not in {
            "submodules: Bump outdated",
            "submodules: Bump releng",
            "subprojects: Bump outdated",
            "subprojects: Prepare for release",
            "Fix some stylistic inconsistencies",
        }:
            filtered_messages.append(commit)
    return filtered_messages


if __name__ == "__main__":
    main()
