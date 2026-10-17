"""Supported-file discovery with exclusions and file-size safeguards."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

SUPPORTED_NAMES = {"Dockerfile", "Containerfile"}
SUPPORTED_SUFFIXES = {".tf", ".yaml", ".yml", ".json", ".dockerfile"}


def is_supported(path: Path) -> bool:
    return path.name in SUPPORTED_NAMES or path.suffix.lower() in SUPPORTED_SUFFIXES


def _excluded(path: Path, root: Path, patterns: list[str]) -> bool:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.as_posix()
    return any(fnmatch(relative, pattern) or fnmatch(f"{relative}/", pattern) for pattern in patterns)


def discover(target: str, exclusions: list[str], max_file_bytes: int) -> tuple[list[Path], int, list[str]]:
    root = Path(target)
    if not root.exists():
        raise ValueError(f"target does not exist: {target}")
    if root.is_symlink():
        raise ValueError("scanning a symlink target is not supported")
    if root.is_file():
        if not is_supported(root):
            return [], 1, [f"unsupported file type skipped: {root}"]
        if root.stat().st_size > max_file_bytes:
            return [], 1, [f"file exceeds max_file_bytes and was skipped: {root}"]
        return [root], 0, []
    if not root.is_dir():
        raise ValueError(f"target is neither a regular file nor a directory: {target}")

    files: list[Path] = []
    skipped = 0
    warnings: list[str] = []
    resolved_root = root.resolve()
    for candidate in root.rglob("*"):
        if candidate.is_symlink():
            skipped += 1
            continue
        if _excluded(candidate, root, exclusions):
            if candidate.is_file():
                skipped += 1
            continue
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            skipped += 1
            continue
        if not is_supported(candidate):
            continue
        try:
            if candidate.stat().st_size > max_file_bytes:
                skipped += 1
                warnings.append(f"file exceeds max_file_bytes and was skipped: {candidate}")
                continue
            if not candidate.resolve().is_relative_to(resolved_root):
                skipped += 1
                warnings.append(f"file outside scan root skipped: {candidate}")
                continue
        except OSError as exc:
            skipped += 1
            warnings.append(f"could not inspect {candidate}: {exc}")
            continue
        files.append(candidate)
    return sorted(files), skipped, warnings
