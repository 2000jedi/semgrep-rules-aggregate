#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path
from typing import Any

import yaml


YAML_SUFFIXES = {".yaml", ".yml"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect Semgrep rule YAML files whose rule languages include C."
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("."),
        help="Directory to scan recursively. Defaults to the current directory.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("collected"),
        help="Directory where matching YAML files are copied. Defaults to collected/.",
    )
    return parser.parse_args()


def iter_yaml_files(source: Path, output: Path) -> list[Path]:
    source = source.resolve()
    output = output.resolve()
    files: list[Path] = []

    for path in source.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in YAML_SUFFIXES:
            continue

        resolved = path.resolve()
        if output == resolved or output in resolved.parents:
            continue

        files.append(path)

    return sorted(files)


def has_c_language(value: Any) -> bool:
    if isinstance(value, str):
        return value.casefold() == "c"

    if isinstance(value, list):
        return any(isinstance(item, str) and item.casefold() == "c" for item in value)

    return False


def rule_targets_c(rule: Any) -> bool:
    if not isinstance(rule, dict):
        return False

    return has_c_language(rule.get("languages")) or has_c_language(rule.get("language"))


def file_contains_c_rule(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8") as handle:
            documents = yaml.safe_load_all(handle)
            for document in documents:
                if not isinstance(document, dict):
                    continue

                rules = document.get("rules")
                if isinstance(rules, list) and any(rule_targets_c(rule) for rule in rules):
                    return True

                if rule_targets_c(document):
                    return True
    except (OSError, yaml.YAMLError, UnicodeDecodeError):
        return False

    return False


def collected_name(source_root: Path, path: Path) -> str:
    relative = path.relative_to(source_root)
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "__", str(relative))
    return Path(normalized).with_suffix(".yaml").name


def collect(source: Path, output: Path) -> int:
    source_root = source.resolve()
    output.mkdir(parents=True, exist_ok=True)

    copied = 0
    for path in iter_yaml_files(source_root, output):
        if not file_contains_c_rule(path):
            continue

        destination = output / collected_name(source_root, path.resolve())
        shutil.copy2(path, destination)
        copied += 1

    return copied


def main() -> None:
    args = parse_args()
    copied = collect(args.source, args.output)
    print(f"Copied {copied} C Semgrep rule file(s) to {args.output}")


if __name__ == "__main__":
    main()
