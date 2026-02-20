#!/usr/bin/env python3
"""Quality gate for changed files.

Rules enforced:
- max line length: 120
- max function size: 30 non-empty, non-comment lines
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional

MAX_LINE_LEN = 120
MAX_FUNCTION_LINES = 30

LINE_EXTS = {
    ".rs",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".sh",
    ".py",
    ".yml",
    ".yaml",
    ".toml",
}

FUNCTION_EXTS = {".rs", ".ts", ".tsx", ".js", ".jsx", ".sh", ".py"}

SKIP_PARTS = {
    ".git",
    "target",
    "dist",
    "node_modules",
    ".angular",
    ".cargo",
    "scripts/tmp",
    "playwright-report",
    "test-results",
}

SKIP_FILES = {
    "Cargo.lock",
    "coverage.json",
    "coverage-unit.json",
    "coverage-unit.txt",
    "package-lock.json",
}

RUST_FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*")
RUST_ATTR = re.compile(r"^\s*#\[")
RUST_CFG_TEST_ATTR = re.compile(r"^\s*#\[\s*cfg\s*\(\s*test\s*\)\s*\]")
RUST_TEST_ATTR = re.compile(r"^\s*#\[\s*(?:tokio::)?test(?:\([^)]*\))?\s*\]")
TS_JS_FN = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\(|"
    r"^\s*(?:public|private|protected|readonly|static|async|\s)+[A-Za-z_$][A-Za-z0-9_$]*\s*\([^;]*\)\s*\{|"
    r"=>\s*\{"
)
SH_FN = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\)\s*\{")
PY_FN = re.compile(r"^\s*(?:async\s+)?def\s+[A-Za-z_][A-Za-z0-9_]*\s*\(")
TS_JS_SKIP_START = ("if", "for", "while", "switch", "catch", "else", "do", "try")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check line/function size constraints")
    parser.add_argument("files", nargs="*", help="Files to validate")
    parser.add_argument("--files-from", help="Path to newline-separated file list")
    parser.add_argument(
        "--changed-lines-only",
        action="store_true",
        help="Check only lines changed since --diff-base",
    )
    parser.add_argument(
        "--diff-base",
        help="Git base revision used with --changed-lines-only (default: HEAD~1)",
    )
    return parser.parse_args()


def load_files(args: argparse.Namespace) -> list[str]:
    files: list[str] = []
    if args.files_from:
        files.extend(Path(args.files_from).read_text(encoding="utf-8").splitlines())
    if args.files:
        files.extend(args.files)
    if files:
        return [f for f in files if f.strip()]
    output = subprocess.check_output(["git", "ls-files"], text=True)
    return [line for line in output.splitlines() if line.strip()]


def skip_path(path: Path) -> bool:
    if path.name in SKIP_FILES:
        return True
    joined = "/".join(path.parts)
    if "scripts/tmp" in joined:
        return True
    return any(part in SKIP_PARTS for part in path.parts)


def target_files(paths: Iterable[str]) -> list[Path]:
    selected: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if not path.exists() or not path.is_file():
            continue
        if skip_path(path):
            continue
        if path.suffix not in LINE_EXTS:
            continue
        selected.append(path)
    return selected


def has_code(line: str, ext: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if ext in {".rs", ".ts", ".tsx", ".js", ".jsx"} and stripped.startswith("//"):
        return False
    if ext in {".sh", ".py"} and stripped.startswith("#"):
        return False
    return True


def strip_inline_comment(line: str, ext: str) -> str:
    if ext in {".rs", ".ts", ".tsx", ".js", ".jsx"}:
        return line.split("//", 1)[0]
    if ext in {".sh", ".py"}:
        return line.split("#", 1)[0]
    return line


def is_function_start(line: str, ext: str) -> bool:
    if ext == ".rs":
        return bool(RUST_FN.search(line))
    if ext in {".ts", ".tsx", ".js", ".jsx"}:
        stripped = line.lstrip()
        for prefix in TS_JS_SKIP_START:
            if stripped.startswith(f"{prefix} ") or stripped.startswith(f"{prefix}("):
                return False
        return bool(TS_JS_FN.search(line))
    if ext == ".sh":
        return bool(SH_FN.search(line))
    if ext == ".py":
        return bool(PY_FN.search(line))
    return False


def find_brace_end(lines: list[str], start: int, ext: str) -> int | None:
    depth = 0
    started = False
    for idx in range(start, len(lines)):
        code = strip_inline_comment(lines[idx], ext)
        if "{" in code:
            started = True
        if not started:
            continue
        depth += code.count("{")
        depth -= code.count("}")
        if depth == 0:
            return idx
    return None


def find_python_end(lines: list[str], start: int) -> int:
    base_indent = len(lines[start]) - len(lines[start].lstrip(" "))
    end = len(lines) - 1
    for idx in range(start + 1, len(lines)):
        line = lines[idx]
        stripped = line.strip()
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= base_indent and not stripped.startswith("#"):
            return idx - 1
        end = idx
    return end


def rust_test_ignored_lines(lines: list[str]) -> set[int]:
    ignored: set[int] = set()
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if not (RUST_CFG_TEST_ATTR.search(line) or RUST_TEST_ATTR.search(line)):
            idx += 1
            continue
        attr_start = idx
        cursor = idx + 1
        while cursor < len(lines) and RUST_ATTR.search(lines[cursor]):
            cursor += 1
        while cursor < len(lines) and not lines[cursor].strip():
            cursor += 1
        if cursor >= len(lines):
            ignored.add(attr_start + 1)
            break
        if lines[cursor].strip().startswith("mod tests") and RUST_CFG_TEST_ATTR.search(line):
            for line_no in range(attr_start + 1, len(lines) + 1):
                ignored.add(line_no)
            break
        end = find_brace_end(lines, cursor, ".rs")
        if end is None:
            ignored.add(attr_start + 1)
            idx = cursor + 1
            continue
        for line_no in range(attr_start + 1, end + 2):
            ignored.add(line_no)
        idx = end + 1
    return ignored


def ignored_lines_for_file(path: Path, lines: list[str]) -> set[int]:
    if path.suffix == ".rs":
        return rust_test_ignored_lines(lines)
    return set()


def count_body_lines(
    lines: list[str],
    start: int,
    end: int,
    ext: str,
    ignored_lines: set[int],
) -> int:
    total = 0
    for idx in range(start, end + 1):
        if (idx + 1) in ignored_lines:
            continue
        if has_code(lines[idx], ext):
            total += 1
    return total


def changed_lines_since(base: str, path: Path) -> Optional[set[int]]:
    if base == "0000000000000000000000000000000000000000":
        return None
    try:
        diff = subprocess.check_output(
            ["git", "diff", "--unified=0", f"{base}...HEAD", "--", str(path)],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return None

    changed: set[int] = set()
    for raw in diff.splitlines():
        if not raw.startswith("@@"):
            continue
        match = re.search(r"\+(\d+)(?:,(\d+))?", raw)
        if not match:
            continue
        start = int(match.group(1))
        span = int(match.group(2) or "1")
        if span <= 0:
            continue
        for number in range(start, start + span):
            changed.add(number)
    return changed


def check_line_lengths(
    path: Path,
    lines: list[str],
    changed_lines: Optional[set[int]],
    ignored_lines: set[int],
) -> list[str]:
    issues: list[str] = []
    for idx, line in enumerate(lines, start=1):
        if idx in ignored_lines:
            continue
        if changed_lines is not None and idx not in changed_lines:
            continue
        if len(line) > MAX_LINE_LEN:
            issues.append(f"{path}:{idx} line length {len(line)} > {MAX_LINE_LEN}")
    return issues


def check_function_lengths(
    path: Path,
    lines: list[str],
    changed_lines: Optional[set[int]],
    ignored_lines: set[int],
) -> list[str]:
    if path.suffix not in FUNCTION_EXTS:
        return []
    issues: list[str] = []
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if not is_function_start(line, path.suffix):
            idx += 1
            continue
        if (idx + 1) in ignored_lines:
            idx += 1
            continue
        if path.suffix == ".py":
            end = find_python_end(lines, idx)
        else:
            end = find_brace_end(lines, idx, path.suffix)
            if end is None:
                idx += 1
                continue
        if changed_lines is not None and (idx + 1) not in changed_lines:
            idx = end + 1
            continue
        total = count_body_lines(lines, idx, end, path.suffix, ignored_lines)
        if total > MAX_FUNCTION_LINES:
            issues.append(
                f"{path}:{idx + 1} function size {total} > {MAX_FUNCTION_LINES} "
                "(non-empty, non-comment lines)"
            )
        idx = end + 1
    return issues


def run() -> int:
    args = parse_args()
    files = target_files(load_files(args))
    if not files:
        print("quality-check: no matching files")
        return 0

    if args.changed_lines_only:
        base = args.diff_base or "HEAD~1"
    else:
        base = ""

    issues: list[str] = []
    for path in files:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        changed_lines = changed_lines_since(base, path) if args.changed_lines_only else None
        ignored_lines = ignored_lines_for_file(path, lines)
        issues.extend(check_line_lengths(path, lines, changed_lines, ignored_lines))
        issues.extend(check_function_lengths(path, lines, changed_lines, ignored_lines))

    if issues:
        print("quality-check failed:")
        for issue in issues:
            print(issue)
        return 1

    print(f"quality-check passed for {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(run())
