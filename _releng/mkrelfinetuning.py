#!/usr/bin/env python3

import json
import sys
from pathlib import Path

import yaml
from mkrelnotes import extract_release_metadata


def main():
    repo_root = Path(__file__).resolve().parent.parent
    frida_repo = Path(sys.argv[1])
    posts_dir = repo_root / "_i18n" / "en" / "_posts"
    output_file = repo_root / "fine_tuning_data.jsonl"
    generate_fine_tuning_data(frida_repo, posts_dir, output_file)


def generate_fine_tuning_data(frida_repo: Path, posts_dir: Path, output_file: Path):
    fine_tuning_data = []

    for file_path in posts_dir.glob("*-released.markdown"):
        print("\nProcessing", file_path)
        version = extract_version_from_markdown(file_path)
        release_metadata = extract_release_metadata(frida_repo, version)
        markdown_content = file_path.read_text(encoding="utf-8")

        fine_tuning_data.append(
            {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an assistant that writes release notes for the Frida open source project.",
                    },
                    {
                        "role": "user",
                        "content": f"Generate release notes for {version}. Output markdown with a YAML front matter. Release metadata:\n```json\n"
                        + json.dumps(release_metadata)
                        + "\n```",
                    },
                    {"role": "assistant", "content": markdown_content},
                ]
            }
        )

    with output_file.open("w", encoding="utf-8") as output:
        for item in fine_tuning_data:
            output.write(json.dumps(item) + "\n")


def extract_version_from_markdown(file_path: Path) -> str:
    content = file_path.read_text(encoding="utf-8")
    front_matter = content.split("---")[1]
    metadata = yaml.safe_load(front_matter)
    raw_version = str(metadata["version"])
    if len(raw_version.split(".")) == 2:
        return raw_version + ".0"
    return raw_version


if __name__ == "__main__":
    main()
