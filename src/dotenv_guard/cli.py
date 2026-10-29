"""Command line entry for dotenv-guard."""

from __future__ import annotations

import argparse
import sys

from dotenv_guard import __version__
from dotenv_guard.scan import Finding, GitError, scan_paths, scan_staged


COMMANDS = {"scan", "check-staged"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dotenv-guard",
        description="Block .env files and flag common secrets before they get committed.",
    )
    parser.add_argument("--version", action="version", version=f"dotenv-guard {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan files or directories (default: current directory)")
    scan.add_argument(
        "paths",
        nargs="*",
        help="Files or directories to scan (default: current directory)",
    )

    staged = sub.add_parser("check-staged", help="Scan files staged in the git index")
    staged.add_argument(
        "--repo",
        default=".",
        help="Path to the git repo (default: current directory)",
    )
    return parser


def normalize(argv: list[str]) -> list[str]:
    """No command means scan. A bare path means scan that path."""
    if not argv:
        return ["scan"]
    if argv[0] in COMMANDS or argv[0].startswith("-"):
        return argv
    return ["scan", *argv]


def _finish(findings: list[Finding], errors: int) -> int:
    if findings:
        for item in findings:
            print(item.format())
        return 1
    if errors:
        return 2
    print("ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(normalize(argv))

    if args.command == "check-staged":
        try:
            findings, errors = scan_staged(args.repo)
        except GitError as exc:
            print(f"dotenv-guard: {exc}", file=sys.stderr)
            return 2
        return _finish(findings, errors)

    paths = args.paths or ["."]
    findings, errors = scan_paths(paths)
    return _finish(findings, errors)
