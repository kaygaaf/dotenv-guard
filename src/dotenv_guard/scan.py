"""Find env files and a short list of common secret patterns."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


# Only the first chunk of a file is scanned. Enough for real secrets,
# and it keeps a stray tarball or vendored blob from blowing up the run.
MAX_BYTES = 1_000_000

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".eggs",
    "__pycache__",
    "node_modules",
    "venv",
    "dist",
    "build",
}

# .env.example and .env.sample are the usual "copy me" templates.
ALLOWED_ENV_NAMES = {".env.example", ".env.sample"}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int | None
    reason: str

    def format(self) -> str:
        if self.line is None:
            return f"{self.path}: {self.reason}"
        return f"{self.path}:{self.line}: {self.reason}"


class GitError(Exception):
    """git was missing, or the path is not a repository."""


@dataclass(frozen=True)
class _Pattern:
    reason: str
    regex: re.Pattern[str]


def _compile(reason: str, pattern: str) -> _Pattern:
    return _Pattern(reason, re.compile(pattern))


# Kept tight on purpose. A loose "password=" check flags half the planet.
PATTERNS: tuple[_Pattern, ...] = (
    _compile("AWS access key", r"\bAKIA[0-9A-Z]{16}\b"),
    _compile(
        "AWS secret key",
        r"""(?i)\baws_secret_access_key\b\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}""",
    ),
    _compile("Stripe live key", r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    _compile("Stripe live key", r"\brk_live_[0-9a-zA-Z]{24,}\b"),
    _compile(
        "private key",
        r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY(?: BLOCK)?-----",
    ),
    _compile("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    _compile(
        "GitHub fine-grained token",
        r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b",
    ),
    _compile("WooCommerce consumer key", r"\bck_[a-fA-F0-9]{40}\b"),
    _compile("WooCommerce consumer secret", r"\bcs_[a-fA-F0-9]{40}\b"),
    _compile("Slack token", r"\bxox[baprs]-[0-9A-Za-z-]{10,80}"),
    _compile("Google API key", r"AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
    _compile("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
)


def is_blocked_env_filename(name: str) -> bool:
    """True for .env and .env.*, except the example/sample templates."""
    base = name.casefold()
    if base in ALLOWED_ENV_NAMES:
        return False
    return base == ".env" or base.startswith(".env.")


def skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.endswith(".egg-info")


def secret_findings(path: str, text: str) -> list[Finding]:
    found: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        seen: set[str] = set()
        for spec in PATTERNS:
            if spec.reason in seen:
                continue
            if spec.regex.search(line):
                seen.add(spec.reason)
                found.append(Finding(path, lineno, spec.reason))
    return found


def scan_content(path: str, data: bytes) -> list[Finding]:
    """Scan an in-memory blob. `path` is the label printed in findings."""
    findings: list[Finding] = []
    if is_blocked_env_filename(Path(path).name):
        findings.append(Finding(path, None, "env file"))

    chunk = data[:MAX_BYTES]
    if b"\0" in chunk:
        return findings

    text = chunk.decode("utf-8", errors="replace")
    findings.extend(secret_findings(path, text))
    return findings


def _display_path(path: Path) -> str:
    try:
        current = Path.cwd().resolve()
        rel = path.resolve().relative_to(current)
    except (OSError, ValueError):
        return path.as_posix()
    text = rel.as_posix()
    return text or "."


def _sort(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda item: (item.path, -1 if item.line is None else item.line))


def _warn(message: str) -> None:
    print(f"dotenv-guard: {message}", file=sys.stderr)


def _scan_file(path: Path, seen: set[Path]) -> tuple[list[Finding], int]:
    display = _display_path(path)
    try:
        real = path.resolve()
    except OSError as exc:
        _warn(f"cannot read {display}: {exc}")
        return [], 1
    if real in seen:
        return [], 0
    seen.add(real)

    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except OSError as exc:
        # Still report a blocked name if we could not read the bytes.
        findings = []
        if is_blocked_env_filename(path.name):
            findings.append(Finding(display, None, "env file"))
        _warn(f"cannot read {display}: {exc.strerror or exc}")
        return findings, 1

    return scan_content(display, data[:MAX_BYTES] if len(data) > MAX_BYTES else data), 0


def _scan_tree(root: Path, seen: set[Path]) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    errors = 0

    if is_blocked_env_filename(root.name):
        return [Finding(_display_path(root), None, "env file")], 0

    def onerror(err: OSError) -> None:
        nonlocal errors
        errors += 1
        filename = getattr(err, "filename", None) or root
        _warn(f"cannot read {filename}: {err.strerror or err}")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=onerror):
        kept: list[str] = []
        for name in dirnames:
            child = Path(dirpath) / name
            if is_blocked_env_filename(name):
                findings.append(Finding(_display_path(child), None, "env file"))
                continue
            if skip_dir(name):
                continue
            kept.append(name)
        dirnames[:] = kept

        for name in filenames:
            child = Path(dirpath) / name
            if child.is_symlink() and not child.exists():
                continue
            found, err = _scan_file(child, seen)
            findings.extend(found)
            errors += err

    return findings, errors


def scan_paths(paths: list[str]) -> tuple[list[Finding], int]:
    """Scan files and directories. Returns findings and a read-error count."""
    findings: list[Finding] = []
    errors = 0
    seen: set[Path] = set()

    for raw in paths:
        path = Path(raw)
        if not path.exists():
            _warn(f"path not found: {raw}")
            errors += 1
            continue
        if path.is_dir():
            found, err = _scan_tree(path, seen)
        elif path.is_file():
            found, err = _scan_file(path, seen)
        else:
            _warn(f"path not found: {raw}")
            errors += 1
            continue
        findings.extend(found)
        errors += err

    return _sort(findings), errors


def _git_message(stderr: bytes) -> str:
    text = stderr.decode("utf-8", "replace").strip()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "git failed"
    message = lines[-1]
    if message.lower().startswith("fatal:"):
        message = message.split(":", 1)[1].strip()
    return message or "git failed"


def staged_names(repo: str) -> list[str]:
    try:
        proc = subprocess.run(
            [
                "git",
                "-C",
                repo,
                "diff",
                "--cached",
                "--name-only",
                "--diff-filter=ACMRT",
                "-z",
            ],
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed") from exc
    if proc.returncode != 0:
        raise GitError(_git_message(proc.stderr))
    raw = proc.stdout.decode("utf-8", "surrogateescape")
    return [name for name in raw.split("\0") if name]


def read_staged(repo: str, name: str) -> bytes | None:
    """Staged blob, truncated to MAX_BYTES. None when git cannot show it."""
    try:
        proc = subprocess.Popen(
            ["git", "-C", repo, "show", f":{name}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed") from exc

    assert proc.stdout is not None and proc.stderr is not None
    try:
        data = proc.stdout.read(MAX_BYTES + 1)
        # A blob bigger than the cap leaves git blocked on the pipe.
        if len(data) > MAX_BYTES and proc.poll() is None:
            proc.kill()
        err = proc.stderr.read()
        rc = proc.wait()
    finally:
        proc.stdout.close()
        proc.stderr.close()

    if rc != 0 and not data:
        _warn(f"cannot read staged {name}: {_git_message(err)}")
        return None
    if len(data) > MAX_BYTES:
        return data[:MAX_BYTES]
    return data


def scan_staged(repo: str) -> tuple[list[Finding], int]:
    """Scan the index. Raises GitError when repo is not a git checkout."""
    findings: list[Finding] = []
    errors = 0
    for name in staged_names(repo):
        data = read_staged(repo, name)
        if data is None:
            errors += 1
            continue
        # git paths are relative to the repo and already use forward slashes.
        findings.extend(scan_content(name, data))
    return _sort(findings), errors
