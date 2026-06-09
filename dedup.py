#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import signal
from pathlib import Path
from typing import Any

import yaml


YAML_SUFFIXES = {".yaml", ".yml"}
PATTERN_KEYS = (
    "pattern",
    "patterns",
    "pattern-either",
    "pattern-regex",
    "pattern-not",
    "pattern-not-inside",
    "pattern-inside",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Keep only C Semgrep rules and deduplicate them by rule id or pattern content. "
            "Defaults to dry-run; pass --apply to rewrite files and delete empty files."
        )
    )
    parser.add_argument(
        "--folder",
        type=Path,
        default=Path("scrap"),
        help="Folder containing scraped YAML files. Defaults to scrap/.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Remove non-C and duplicate rules, rewrite mixed files, and delete files that have "
            "no rules left. Without this flag, only report planned changes."
        ),
    )
    return parser.parse_args()


def iter_yaml_files(folder: Path) -> list[Path]:
    return sorted(
        path
        for path in folder.iterdir()
        if path.is_file() and path.suffix.lower() in YAML_SUFFIXES
    )


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def load_documents(path: Path) -> list[Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return list(yaml.safe_load_all(handle))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return []


def pattern_values(rule: dict[str, Any]) -> list[Any]:
    values: list[Any] = []
    for key in PATTERN_KEYS:
        if key in rule:
            values.append({key: rule[key]})
    return values


def rule_label(rule: dict[str, Any]) -> str:
    rule_id = rule.get("id")
    if isinstance(rule_id, str):
        return rule_id
    return "<rule without id>"


def has_c_language(value: Any) -> bool:
    if isinstance(value, str):
        return value.casefold() == "c"

    if isinstance(value, list):
        return any(isinstance(item, str) and item.casefold() == "c" for item in value)

    return False


def rule_targets_c(rule: dict[str, Any]) -> bool:
    return has_c_language(rule.get("languages")) or has_c_language(rule.get("language"))


def rule_duplicate_reason(
    rule: dict[str, Any],
    seen_ids: dict[str, tuple[Path, str]],
    seen_patterns: dict[str, tuple[Path, str]],
) -> str | None:
    rule_id = rule.get("id")
    if isinstance(rule_id, str) and rule_id in seen_ids:
        seen_path, seen_rule = seen_ids[rule_id]
        return f"id {rule_id!r} already seen in {seen_path} ({seen_rule})"

    for pattern in pattern_values(rule):
        fingerprint = canonical(pattern)
        if fingerprint in seen_patterns:
            seen_path, seen_rule = seen_patterns[fingerprint]
            return f"pattern already seen in {seen_path} ({seen_rule})"

    return None


def remember_rule(
    path: Path,
    rule: dict[str, Any],
    seen_ids: dict[str, tuple[Path, str]],
    seen_patterns: dict[str, tuple[Path, str]],
) -> None:
    label = rule_label(rule)
    rule_id = rule.get("id")
    if isinstance(rule_id, str):
        seen_ids.setdefault(rule_id, (path, label))

    for pattern in pattern_values(rule):
        seen_patterns.setdefault(canonical(pattern), (path, label))


def filter_rule(
    path: Path,
    rule: dict[str, Any],
    seen_ids: dict[str, tuple[Path, str]],
    seen_patterns: dict[str, tuple[Path, str]],
) -> tuple[bool, str | None, str | None]:
    if not rule_targets_c(rule):
        return False, "non_c", "not a C-language rule"

    reason = rule_duplicate_reason(rule, seen_ids, seen_patterns)
    if reason:
        return False, "duplicate", reason

    remember_rule(path, rule, seen_ids, seen_patterns)
    return True, None, None


def filter_documents(
    path: Path,
    seen_ids: dict[str, tuple[Path, str]],
    seen_patterns: dict[str, tuple[Path, str]],
) -> tuple[list[Any], list[str], list[str], bool]:
    documents = load_documents(path)
    kept_documents: list[Any] = []
    removed_duplicates: list[str] = []
    removed_non_c: list[str] = []
    changed = False

    for document in documents:
        if not isinstance(document, dict):
            kept_documents.append(document)
            continue

        document_rules = document.get("rules")
        if isinstance(document_rules, list):
            kept_rules: list[Any] = []
            for item in document_rules:
                if not isinstance(item, dict):
                    kept_rules.append(item)
                    continue

                keep, reason_type, reason = filter_rule(path, item, seen_ids, seen_patterns)
                if not keep:
                    if reason_type == "non_c":
                        removed_non_c.append(f"{rule_label(item)}: {reason}")
                    elif reason_type == "duplicate":
                        removed_duplicates.append(f"{rule_label(item)}: {reason}")
                    changed = True
                    continue

                kept_rules.append(item)

            if kept_rules:
                updated_document = dict(document)
                updated_document["rules"] = kept_rules
                kept_documents.append(updated_document)
            else:
                changed = True
            continue

        keep, reason_type, reason = filter_rule(path, document, seen_ids, seen_patterns)
        if not keep:
            if reason_type == "non_c":
                removed_non_c.append(f"{rule_label(document)}: {reason}")
            elif reason_type == "duplicate":
                removed_duplicates.append(f"{rule_label(document)}: {reason}")
            changed = True
            continue

        kept_documents.append(document)

    return kept_documents, removed_duplicates, removed_non_c, changed


def write_documents(path: Path, documents: list[Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump_all(documents, handle, sort_keys=False, allow_unicode=False)


def deduplicate(folder: Path, apply: bool) -> int:
    seen_ids: dict[str, tuple[Path, str]] = {}
    seen_patterns: dict[str, tuple[Path, str]] = {}
    removed_duplicate_rules = 0
    removed_non_c_rules = 0
    rewritten_files = 0
    deleted_files = 0

    for path in iter_yaml_files(folder):
        kept_documents, removed_duplicates, removed_non_c, changed = filter_documents(
            path,
            seen_ids,
            seen_patterns,
        )
        if not changed:
            continue

        removed_duplicate_rules += len(removed_duplicates)
        removed_non_c_rules += len(removed_non_c)
        for reason in removed_non_c:
            print(f"{'remove non-C' if apply else 'would remove non-C'}: {path}: {reason}")
        for reason in removed_duplicates:
            print(f"{'remove duplicate' if apply else 'would remove duplicate'}: {path}: {reason}")

        if kept_documents:
            rewritten_files += 1
            print(f"{'rewrite' if apply else 'would rewrite'}: {path}")
            if apply:
                write_documents(path, kept_documents)
        else:
            deleted_files += 1
            print(f"{'delete' if apply else 'would delete'}: {path}")
            if apply:
                path.unlink()

    verb = "Removed" if apply else "Found"
    print(
        f"{verb} {removed_non_c_rules} non-C rule(s) and "
        f"{removed_duplicate_rules} duplicate C rule(s); "
        f"{'rewrote' if apply else 'would rewrite'} {rewritten_files} file(s); "
        f"{'deleted' if apply else 'would delete'} {deleted_files} file(s)"
    )
    return removed_non_c_rules + removed_duplicate_rules


def main() -> int:
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    args = parse_args()
    if not args.folder.is_dir():
        print(f"Not a directory: {args.folder}")
        return 1

    deduplicate(args.folder, args.apply)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
