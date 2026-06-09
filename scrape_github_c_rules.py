#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml


GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
YAML_SUFFIXES = {".yaml", ".yml"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Search GitHub for semgrep-rules repositories, shallow-clone them "
            "under /tmp, and collect Semgrep YAML rules whose languages include C."
        )
    )
    parser.add_argument(
        "--query",
        default="semgrep-rules",
        help="GitHub repository search query. Defaults to semgrep-rules.",
    )
    parser.add_argument(
        "--max-repos",
        type=int,
        default=1000,
        help="Maximum repositories to clone. GitHub search caps results at 1000.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("scrap"),
        help="Directory where matching YAML files are copied. Defaults to scrap/.",
    )
    parser.add_argument(
        "--tmp-root",
        type=Path,
        default=Path("/tmp/semgrep-rules-scrape"),
        help="Temporary clone root. Defaults to /tmp/semgrep-rules-scrape.",
    )
    parser.add_argument(
        "--keep-clones",
        action="store_true",
        help="Keep existing clones and fetch fresh clones into missing directories only.",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.0,
        help="Seconds to sleep between GitHub API requests.",
    )
    return parser.parse_args()


def github_token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def github_request(url: str) -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "semgrep-c-rule-scraper",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def search_repositories(query: str, max_repos: int, sleep_seconds: float) -> list[dict[str, Any]]:
    repos: list[dict[str, Any]] = []
    per_page = 100
    page = 1

    while len(repos) < max_repos:
        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": str(per_page),
            "page": str(page),
        }
        url = f"{GITHUB_SEARCH_URL}?{urllib.parse.urlencode(params)}"
        payload = github_request(url)
        items = payload.get("items", [])
        if not items:
            break

        repos.extend(items)
        if len(items) < per_page:
            break

        page += 1
        if page > 10:
            break
        if sleep_seconds:
            time.sleep(sleep_seconds)

    return repos[:max_repos]


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "__", value).strip("_")


def clone_path(tmp_root: Path, full_name: str) -> Path:
    return tmp_root / safe_component(full_name)


def collected_name(full_name: str, repo_root: Path, path: Path) -> str:
    relative = path.relative_to(repo_root)
    source_name = f"{full_name}/{relative}"
    return Path(safe_component(str(source_name))).with_suffix(".yaml").name


def clone_repository(repo: dict[str, Any], tmp_root: Path, keep_clones: bool) -> Path | None:
    full_name = repo["full_name"]
    destination = clone_path(tmp_root, full_name)

    if destination.exists() and not keep_clones:
        shutil.rmtree(destination)

    if destination.exists():
        return destination

    clone_url = repo["clone_url"]
    command = ["git", "clone", "--depth", "1", clone_url, str(destination)]
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode != 0:
        print(f"clone failed: {full_name}: {result.stderr.strip()}", file=sys.stderr)
        return None

    return destination


def iter_yaml_files(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in repo_root.rglob("*"):
        if ".git" in path.parts:
            continue
        if path.is_file() and path.suffix.lower() in YAML_SUFFIXES:
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
            for document in yaml.safe_load_all(handle):
                if not isinstance(document, dict):
                    continue

                rules = document.get("rules")
                if isinstance(rules, list) and any(rule_targets_c(rule) for rule in rules):
                    return True

                if rule_targets_c(document):
                    return True
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return False

    return False


def copy_c_rules(full_name: str, repo_root: Path, output: Path) -> int:
    copied = 0
    for path in iter_yaml_files(repo_root):
        if not file_contains_c_rule(path):
            continue

        destination = output / collected_name(full_name, repo_root, path)
        shutil.copy2(path, destination)
        copied += 1

    return copied


def log_path(output: Path) -> Path:
    return output / "log.txt"


def read_completed_repos(output: Path) -> set[str]:
    path = log_path(output)
    if not path.exists():
        return set()

    try:
        return {
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    except OSError:
        return set()


def append_completed_repo(output: Path, full_name: str) -> None:
    with log_path(output).open("a", encoding="utf-8") as handle:
        handle.write(f"{full_name}\n")


def main() -> int:
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    args.tmp_root.mkdir(parents=True, exist_ok=True)

    repos = search_repositories(args.query, args.max_repos, args.sleep)
    print(f"Found {len(repos)} repos for query: {args.query}")

    completed_repos = read_completed_repos(args.output)
    if completed_repos:
        print(f"Skipping {len(completed_repos)} repo(s) already listed in {log_path(args.output)}")

    total_files = 0
    cloned_repos = 0
    skipped_repos = 0
    for index, repo in enumerate(repos, start=1):
        full_name = repo["full_name"]
        if full_name in completed_repos:
            skipped_repos += 1
            print(f"[{index}/{len(repos)}] {full_name} (skipped)")
            continue

        print(f"[{index}/{len(repos)}] {full_name}")
        repo_root = clone_repository(repo, args.tmp_root, args.keep_clones)
        if repo_root is None:
            continue

        cloned_repos += 1
        copied = copy_c_rules(full_name, repo_root, args.output)
        total_files += copied
        append_completed_repo(args.output, full_name)
        completed_repos.add(full_name)
        print(f"  copied {copied}")

    print(
        f"Skipped {skipped_repos} repo(s); cloned {cloned_repos} repo(s); "
        f"copied {total_files} C Semgrep YAML file(s) to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
