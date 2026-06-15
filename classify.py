#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import yaml


LOGICAL_LEVELS = {
    -1: "Unclassified / no Semgrep logical pattern operator found",
    0: "Only regex pattern(s)",
    1: "Single or multiple positive pattern(s)",
    2: "Conjunction / Intersection",
    3: "Negation / Filtering",
    4: "Containment (inclusive)",
    5: "Containment (exclusive)",
}

LOGICAL_GROUPS = {
    0: "A1",
    1: "A2",
    2: "A3",
    3: "A4",
    4: "A5",
    5: "A6",
}

LOGICAL_PRIORITY = [
    (5, "pattern-not-inside"),
    (4, "pattern-inside"),
    (3, "pattern-not"),
    (2, "patterns"),
    (1, "pattern-either"),
    (1, "pattern"),
    (0, "pattern-regex"),
]

PATTERN_KEYS = {
    "pattern",
    "pattern-either",
    "patterns",
    "pattern-not",
    "pattern-inside",
    "pattern-not-inside",
    "pattern-regex",
}

PATTERN_TEXT_KEYS = {
    "pattern",
    "pattern-not",
    "pattern-inside",
    "pattern-not-inside",
    "pattern-regex",
}

PATTERNS_KEY = "patterns"
PATTERN_EITHER_KEY = "pattern-either"

METAVARIABLE_REGEX_KEYS = {"metavariable-regex"}
METAVARIABLE_PATTERN_KEYS = {"metavariable-pattern"}
METAVARIABLE_COMPARISON_TYPE_KEYS = {"metavariable-comparison", "metavariable-type"}

PLAIN_METAVAR_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_])
    \$(?!\.\.\.)
    [A-Z_][A-Z0-9_]*
    \b
    """,
    re.VERBOSE,
)

ELLIPSIS_METAVAR_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_])
    \$\.\.\.
    [A-Z_][A-Z0-9_]*
    \b
    """,
    re.VERBOSE,
)

DEEP_EXPR_RE = re.compile(
    r"""
    <\s*
    \.\.\.
    (?:
        [^<>]
        |
        <[^<>]*>
    )*?
    \.\.\.
    \s*>
    """,
    re.VERBOSE | re.DOTALL,
)

UNNAMED_ELLIPSIS_RE = re.compile(
    r"""
    (?<![\w$])
    \.\.\.
    (?!\w)
    """,
    re.VERBOSE,
)

BINDING_FIELDS = [
    ("B1_no_metavariable", "B1. no metavariable"),
    ("B2_metavariable_binding", "B2. metavariable binding"),
    ("B3_repeated_metavariable", "B3. repeated metavariable / equality / backreference"),
    ("B3_5_redundant_metavariable", "B3.5. redundant metavariable"),
    ("B4_metavariable_regex", "B4. metavariable-regex"),
    ("B5_metavariable_pattern", "B5. metavariable-pattern"),
    (
        "B6_metavariable_comparison_or_type",
        "B6. metavariable-comparison / metavariable-type",
    ),
]

SHAPE_FIELDS = [
    ("has_no_metavar", "C1", "No metavariable in pattern text"),
    ("has_plain_metavar", "C2", "Plain metavariable $X"),
    ("has_unnamed_ellipsis", "C3", "Unnamed ellipsis ..."),
    ("has_ellipsis_metavar", "C4", "Ellipsis metavariable $...X"),
    ("has_deep_expression", "C5", "Deep expression <... P ...>"),
    ("has_no_pattern_fields", "C6", "No pattern fields"),
]

ROW_FIELDS = [
    "file",
    "directory",
    "document_index",
    "rule_index",
    "rule_id",
    "logical_group",
    "logical_class",
    "operators",
    "B1_no_metavariable",
    "B2_metavariable_binding",
    "B3_repeated_metavariable",
    "B3_5_redundant_metavariable",
    "B4_metavariable_regex",
    "B5_metavariable_pattern",
    "B6_metavariable_comparison_or_type",
    "metavars",
    "repeated_metavars",
    "binding_scopes_json",
    "pattern_count",
    "has_no_metavar",
    "has_plain_metavar",
    "has_unnamed_ellipsis",
    "has_ellipsis_metavar",
    "has_deep_expression",
    "has_no_pattern_fields",
    "shape_groups",
    "shape_labels",
]


def iter_yaml_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}:
            yield path


def load_yaml_documents(path: Path) -> list[Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return list(yaml.safe_load_all(handle))
    except yaml.YAMLError as error:
        print(f"[WARN] YAML parse error in {path}: {error}", file=sys.stderr)
    except UnicodeDecodeError as error:
        print(f"[WARN] Encoding error in {path}: {error}", file=sys.stderr)
    except OSError as error:
        print(f"[WARN] Read error in {path}: {error}", file=sys.stderr)
    return []


def extract_rules(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []

    if isinstance(document.get("rules"), list):
        return [rule for rule in document["rules"] if isinstance(rule, dict)]

    if "id" in document:
        return [document]

    return []


def collect_keys(node: Any, keys: set[str] | None = None) -> set[str]:
    if keys is None:
        keys = set()

    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str):
                keys.add(key)
            collect_keys(value, keys)
    elif isinstance(node, list):
        for item in node:
            collect_keys(item, keys)

    return keys


def collect_operator_keys(node: Any, keys: list[str] | None = None) -> list[str]:
    if keys is None:
        keys = []

    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str):
                keys.append(key)
            collect_operator_keys(value, keys)
    elif isinstance(node, list):
        for item in node:
            collect_operator_keys(item, keys)

    return keys


def classify_logical(rule: dict[str, Any]) -> dict[str, Any]:
    operator_set = set(collect_operator_keys(rule))

    for level, operator in LOGICAL_PRIORITY:
        if operator in operator_set:
            return {
                "logical_level": level,
                "logical_group": LOGICAL_GROUPS[level],
                "logical_class": LOGICAL_LEVELS[level],
                "operators": sorted(operator_set),
            }

    return {
        "logical_level": -1,
        "logical_group": "unclassified",
        "logical_class": LOGICAL_LEVELS[-1],
        "operators": sorted(operator_set),
    }


def metavars_in_text(text: str) -> list[str]:
    return [
        *(match.group(0) for match in PLAIN_METAVAR_RE.finditer(text)),
        *(match.group(0) for match in ELLIPSIS_METAVAR_RE.finditer(text)),
    ]


def add_counters(left: Counter[str], right: Counter[str]) -> Counter[str]:
    result = Counter(left)
    result.update(right)
    return result


def collect_binding_scopes(node: Any) -> list[Counter[str]]:
    if isinstance(node, str):
        return [Counter(metavars_in_text(node))]

    if isinstance(node, list):
        scopes: list[Counter[str]] = [Counter()]
        for item in node:
            item_scopes = collect_binding_scopes(item)
            scopes = [add_counters(left, right) for left in scopes for right in item_scopes]
        return scopes

    if isinstance(node, dict):
        if PATTERN_EITHER_KEY in node:
            value = node[PATTERN_EITHER_KEY]
            branch_scopes: list[Counter[str]] = []
            branches = value if isinstance(value, list) else [value]
            for branch in branches:
                branch_scopes.extend(collect_binding_scopes(branch))

            other_items = {key: value for key, value in node.items() if key != PATTERN_EITHER_KEY}
            if other_items:
                other_scopes = collect_binding_scopes(other_items)
                return [
                    add_counters(branch, other)
                    for branch in branch_scopes
                    for other in other_scopes
                ]

            return branch_scopes or [Counter()]

        if PATTERNS_KEY in node:
            value = node[PATTERNS_KEY]
            children = value if isinstance(value, list) else [value]
            scopes: list[Counter[str]] = [Counter()]

            for child in children:
                child_scopes = collect_binding_scopes(child)
                scopes = [
                    add_counters(left, right)
                    for left in scopes
                    for right in child_scopes
                ]

            other_items = {key: value for key, value in node.items() if key != PATTERNS_KEY}
            if other_items:
                other_scopes = collect_binding_scopes(other_items)
                return [
                    add_counters(scope, other)
                    for scope in scopes
                    for other in other_scopes
                ]

            return scopes

        scopes = [Counter()]
        for key, value in node.items():
            if isinstance(key, str) and key in PATTERN_TEXT_KEYS and isinstance(value, str):
                child_scopes = [Counter(metavars_in_text(value))]
            else:
                child_scopes = collect_binding_scopes(value)

            scopes = [
                add_counters(left, right)
                for left in scopes
                for right in child_scopes
            ]

        return scopes

    return [Counter()]


def collect_constraint_metavars(node: Any) -> set[str]:
    found: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "metavariable" and isinstance(child, str):
                    found.update(metavars_in_text(child))
                else:
                    visit(child)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(node)
    return found


def classify_binding(rule: dict[str, Any]) -> dict[str, Any]:
    keys = collect_keys(rule)
    scopes = collect_binding_scopes(rule)
    all_metavars: set[str] = set()
    repeated_metavars: set[str] = set()

    for scope in scopes:
        for metavar, count in scope.items():
            all_metavars.add(metavar)
            if count >= 2:
                repeated_metavars.add(metavar)

    all_metavars.update(collect_constraint_metavars(rule))
    has_metavariable_binding = bool(all_metavars)

    return {
        "B1_no_metavariable": not has_metavariable_binding,
        "B2_metavariable_binding": has_metavariable_binding,
        "B3_repeated_metavariable": bool(repeated_metavars),
        "B4_metavariable_regex": bool(keys & METAVARIABLE_REGEX_KEYS),
        "B5_metavariable_pattern": bool(keys & METAVARIABLE_PATTERN_KEYS),
        "B6_metavariable_comparison_or_type": bool(keys & METAVARIABLE_COMPARISON_TYPE_KEYS),
        "metavars": sorted(all_metavars),
        "repeated_metavars": sorted(repeated_metavars),
        "binding_scopes": [dict(sorted(scope.items())) for scope in scopes if scope],
    }


def collect_pattern_strings(rule: dict[str, Any]) -> list[str]:
    patterns: list[str] = []

    def visit(node: Any, parent_key: str = "") -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if not isinstance(key, str):
                    continue
                if key in PATTERN_KEYS:
                    if isinstance(value, str):
                        patterns.append(value)
                    else:
                        visit(value, key)
                else:
                    visit(value, key)
        elif isinstance(node, list):
            for item in node:
                visit(item, parent_key)
        elif isinstance(node, str) and parent_key in PATTERN_KEYS:
            patterns.append(node)

    visit(rule)
    return patterns


def mask_regex(text: str, regex: re.Pattern[str]) -> str:
    return regex.sub(lambda match: " " * (match.end() - match.start()), text)


def classify_pattern_text(text: str) -> set[str]:
    labels: set[str] = set()

    if PLAIN_METAVAR_RE.search(text):
        labels.add("plain_metavar")
    else:
        labels.add("no_metavar")

    if ELLIPSIS_METAVAR_RE.search(text):
        labels.add("ellipsis_metavar")

    if DEEP_EXPR_RE.search(text):
        labels.add("deep_expression")

    masked = mask_regex(text, DEEP_EXPR_RE)
    masked = mask_regex(masked, ELLIPSIS_METAVAR_RE)
    if UNNAMED_ELLIPSIS_RE.search(masked):
        labels.add("unnamed_ellipsis")

    return labels


def is_plain_pattern_branch(node: Any) -> str | None:
    if not isinstance(node, dict):
        return None

    if set(node) != {"pattern"}:
        return None

    pattern = node["pattern"]
    if not isinstance(pattern, str):
        return None

    return pattern


def is_redundant_metavariable_pattern_either(node: Any) -> bool:
    if not isinstance(node, dict) or PATTERN_EITHER_KEY not in node:
        return False

    branches = node[PATTERN_EITHER_KEY]
    if not isinstance(branches, list) or len(branches) < 2:
        return False

    saw_metavariable = False
    for branch in branches:
        pattern = is_plain_pattern_branch(branch)
        if pattern is None:
            return False

        metavars = metavars_in_text(pattern)
        if metavars:
            saw_metavariable = True

        if any(count > 1 for count in Counter(metavars).values()):
            return False

    return saw_metavariable


def is_non_repeating_metavariable_pattern(pattern: str) -> bool:
    metavars = metavars_in_text(pattern)
    return bool(metavars) and all(count == 1 for count in Counter(metavars).values())


def has_redundant_metavariable_shape(node: Any) -> bool:
    if isinstance(node, dict):
        if PATTERN_EITHER_KEY in node:
            if is_redundant_metavariable_pattern_either(node):
                return True

            return any(
                has_redundant_metavariable_shape(value)
                for key, value in node.items()
                if key != PATTERN_EITHER_KEY
            )

        pattern = is_plain_pattern_branch(node)
        if pattern is not None and is_non_repeating_metavariable_pattern(pattern):
            return True

        return any(has_redundant_metavariable_shape(value) for value in node.values())

    if isinstance(node, list):
        return any(has_redundant_metavariable_shape(item) for item in node)

    return False


def classify_shape(rule: dict[str, Any]) -> dict[str, Any]:
    pattern_strings = collect_pattern_strings(rule)
    labels: set[str] = set()

    for text in pattern_strings:
        labels.update(classify_pattern_text(text))

    if not pattern_strings:
        labels.add("no_pattern_fields")

    has_redundant_metavariable = has_redundant_metavariable_shape(rule)
    if has_redundant_metavariable:
        labels.add("B3.5_redundant_metavariable")

    return {
        "pattern_count": len(pattern_strings),
        "has_no_metavar": "no_metavar" in labels,
        "has_plain_metavar": "plain_metavar" in labels,
        "has_unnamed_ellipsis": "unnamed_ellipsis" in labels,
        "has_ellipsis_metavar": "ellipsis_metavar" in labels,
        "has_deep_expression": "deep_expression" in labels,
        "B3_5_redundant_metavariable": has_redundant_metavariable,
        "has_no_pattern_fields": "no_pattern_fields" in labels,
        "shape_labels": sorted(labels),
    }


def group_directory(root: Path, yaml_file: Path, group_depth: int) -> str:
    relative_parent = yaml_file.relative_to(root).parent
    if str(relative_parent) == ".":
        return "."

    parts = relative_parent.parts
    if group_depth <= 0:
        return str(relative_parent)

    return str(Path(*parts[:group_depth]))


def analyze_folder(root: Path, group_depth: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for yaml_file in sorted(iter_yaml_files(root)):
        documents = load_yaml_documents(yaml_file)

        for document_index, document in enumerate(documents):
            for rule_index, rule in enumerate(extract_rules(document)):
                logical = classify_logical(rule)
                binding = classify_binding(rule)
                shape = classify_shape(rule)
                shape_groups = [
                    group
                    for field, group, _label in SHAPE_FIELDS
                    if shape[field]
                ]

                rows.append(
                    {
                        "file": str(yaml_file),
                        "directory": group_directory(root, yaml_file, group_depth),
                        "document_index": document_index,
                        "rule_index": rule_index,
                        "rule_id": rule.get("id", ""),
                        "logical_group": logical["logical_group"],
                        "logical_class": logical["logical_class"],
                        "operators": ",".join(logical["operators"]),
                        "B1_no_metavariable": binding["B1_no_metavariable"],
                        "B2_metavariable_binding": binding["B2_metavariable_binding"],
                        "B3_repeated_metavariable": binding["B3_repeated_metavariable"],
                        "B4_metavariable_regex": binding["B4_metavariable_regex"],
                        "B5_metavariable_pattern": binding["B5_metavariable_pattern"],
                        "B6_metavariable_comparison_or_type": binding[
                            "B6_metavariable_comparison_or_type"
                        ],
                        "metavars": ",".join(binding["metavars"]),
                        "repeated_metavars": ",".join(binding["repeated_metavars"]),
                        "binding_scopes_json": json.dumps(binding["binding_scopes"]),
                        "pattern_count": shape["pattern_count"],
                        "has_no_metavar": shape["has_no_metavar"],
                        "has_plain_metavar": shape["has_plain_metavar"],
                        "has_unnamed_ellipsis": shape["has_unnamed_ellipsis"],
                        "has_ellipsis_metavar": shape["has_ellipsis_metavar"],
                        "has_deep_expression": shape["has_deep_expression"],
                        "B3_5_redundant_metavariable": shape[
                            "B3_5_redundant_metavariable"
                        ],
                        "has_no_pattern_fields": shape["has_no_pattern_fields"],
                        "shape_groups": ",".join(shape_groups),
                        "shape_labels": ",".join(shape["shape_labels"]),
                    }
                )

    return rows


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    logical_counts = Counter(row["logical_group"] for row in rows)
    logical_groups = [
        (group, LOGICAL_LEVELS[level])
        for level, group in sorted(LOGICAL_GROUPS.items())
    ]
    if logical_counts["unclassified"]:
        logical_groups.append(("unclassified", LOGICAL_LEVELS[-1]))

    return {
        "total_rules": total,
        "logical": {
            group: {
                "label": label,
                "count": logical_counts[group],
                "percent": (logical_counts[group] / total * 100.0) if total else 0.0,
            }
            for group, label in logical_groups
        },
        "binding": {
            field: {
                "label": label,
                "count": sum(1 for row in rows if row[field]),
                "percent": (
                    sum(1 for row in rows if row[field]) / total * 100.0
                    if total
                    else 0.0
                ),
            }
            for field, label in BINDING_FIELDS
        },
        "shape": {
            field: {
                "group": group,
                "label": label,
                "count": sum(1 for row in rows if row[field]),
                "percent": (
                    sum(1 for row in rows if row[field]) / total * 100.0
                    if total
                    else 0.0
                ),
            }
            for field, group, label in SHAPE_FIELDS
        },
    }


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    directories = sorted({row["directory"] for row in rows})
    return {
        "global": summarize_rows(rows),
        "directories": {
            directory: summarize_rows([row for row in rows if row["directory"] == directory])
            for directory in directories
        },
    }


def print_metric_block(title: str, summary: dict[str, Any]) -> None:
    total = summary["total_rules"]
    print(f"{title}: {total} rule(s)")
    print("  Logical:")
    for group, data in summary["logical"].items():
        print(
            f"    {group}. {data['label']}: "
            f"{data['count']} ({data['percent']:.2f}%)"
        )

    print("  Binding:")
    for data in summary["binding"].values():
        print(f"    {data['label']}: {data['count']} ({data['percent']:.2f}%)")

    print("  Shape:")
    for data in summary["shape"].values():
        print(
            f"    {data['group']}. {data['label']}: "
            f"{data['count']} ({data['percent']:.2f}%)"
        )


def escape_latex(value: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in value)


def print_latex_global_table(global_summary: dict[str, Any]) -> None:
    print()
    print("LaTeX Table:")
    print(r"\begin{table}[htbp]")
    print(r"\centering")
    print(r"\begin{tabular}{llrr}")
    print(r"\toprule")
    print(r"Category & Description & Count & Percent \\")
    print(r"\midrule")

    logical_items = list(global_summary["logical"].items())
    binding_items = list(global_summary["binding"].values())
    shape_items = list(global_summary["shape"].values())

    for group, data in logical_items:
        print(
            f"{escape_latex(group)} & {escape_latex(data['label'])} & "
            f"{data['count']} & {data['percent']:.2f}\\% \\\\"
        )

    print(r"\midrule")
    for data in binding_items:
        label, description = data["label"].split(". ", 1)
        print(
            f"{escape_latex(label)} & {escape_latex(description)} & "
            f"{data['count']} & {data['percent']:.2f}\\% \\\\"
        )

    print(r"\midrule")
    for data in shape_items:
        print(
            f"{escape_latex(data['group'])} & {escape_latex(data['label'])} & "
            f"{data['count']} & {data['percent']:.2f}\\% \\\\"
        )

    print(r"\bottomrule")
    print(r"\end{tabular}")
    print(r"\caption{Global Semgrep rule classification summary.}")
    print(r"\end{table}")


def print_summary(summary: dict[str, Any], directory_limit: int | None) -> None:
    print_metric_block("Global", summary["global"])

    directories = summary["directories"]
    if directories:
        print()
        print("Per Directory:")
        shown = 0
        for directory, directory_summary in directories.items():
            if directory_limit is not None and shown >= directory_limit:
                remaining = len(directories) - shown
                print(f"  ... {remaining} more director{'y' if remaining == 1 else 'ies'}")
                break
            print_metric_block(f"  {directory}", directory_summary)
            shown += 1

    print_latex_global_table(summary["global"])


def write_csv(rows: list[dict[str, Any]], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ROW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def write_json(data: Any, output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Classify Semgrep rules by logical operation, metavariable binding, "
            "and pattern shape. Prints global and per-directory summaries."
        )
    )
    parser.add_argument("input_folder", type=Path, help="Directory containing Semgrep YAML rules.")
    parser.add_argument("--csv", type=Path, help="Optional per-rule CSV output path.")
    parser.add_argument("--json", type=Path, help="Optional per-rule JSON output path.")
    parser.add_argument("--summary-json", type=Path, help="Optional summary JSON output path.")
    parser.add_argument(
        "--group-depth",
        type=int,
        default=1,
        help=(
            "Number of path components under input_folder to use for directory summaries. "
            "Use 0 for each file's full parent directory. Defaults to 1."
        ),
    )
    parser.add_argument(
        "--directory-limit",
        type=int,
        default=None,
        help="Limit printed per-directory summaries. JSON outputs still include all directories.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.input_folder.exists():
        print(f"Error: input folder does not exist: {args.input_folder}", file=sys.stderr)
        return 1

    if not args.input_folder.is_dir():
        print(f"Error: input path is not a directory: {args.input_folder}", file=sys.stderr)
        return 1

    root = args.input_folder.resolve()
    rows = analyze_folder(root, args.group_depth)
    summary = build_summary(rows)
    print_summary(summary, args.directory_limit)

    if args.csv:
        write_csv(rows, args.csv)
        print(f"\nWrote CSV: {args.csv}")

    if args.json:
        write_json(rows, args.json)
        print(f"Wrote JSON: {args.json}")

    if args.summary_json:
        write_json(summary, args.summary_json)
        print(f"Wrote summary JSON: {args.summary_json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
