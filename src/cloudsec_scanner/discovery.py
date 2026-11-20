"""Supported-file discovery with exclusions and file-size safeguards."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

from cloudsec_scanner.lockfiles import LOCK_NAMES

SUPPORTED_NAMES = {"Dockerfile", "Containerfile"} | LOCK_NAMES
SUPPORTED_SUFFIXES = {".tf", ".yaml", ".yml", ".json", ".dockerfile"}


SECRET_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".sh", ".bash", ".ps1", ".env", ".ini", ".cfg", ".conf", ".toml", ".properties", ".pem", ".key", ".txt", ".go", ".java", ".rb", ".php", ".cs", ".rs", ".xml"}
SECRET_NAMES = {".env", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "Makefile"}

def is_secret_candidate(path: Path) -> bool:
    return is_supported(path) or path.name in SECRET_NAMES or path.name.startswith(".env.") or path.suffix.lower() in SECRET_SUFFIXES


def is_supported(path: Path) -> bool:
    """Return whether a file type is handled by the scanner."""
    return path.name in SUPPORTED_NAMES or path.suffix.lower() in SUPPORTED_SUFFIXES


def _relative_posix(path: Path, root: Path) -> str:
    """Return a path relative to the scan root, using POSIX separators."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _matches_exclusion(relative: str, pattern: str) -> bool:
    """Match a path against a glob, including directory-style patterns."""
    normalized = pattern.replace("\\", "/").strip()
    if not normalized:
        return False

    relative = relative.strip("/")
    directory_form = f"{relative}/"

    if (
        fnmatch(relative, normalized)
        or fnmatch(directory_form, normalized)
        or fnmatch(f"{relative}/", normalized)
    ):
        return True

    # A pattern such as "vendor/**" also excludes the "vendor" directory
    # itself, so its descendants cannot bypass the exclusion.
    if normalized.endswith("/**"):
        prefix = normalized[:-3].rstrip("/")
        if relative == prefix:
            return True

    return False


def _excluded(path: Path, root: Path, patterns: list[str]) -> bool:
    """Exclude a path if it or any ancestor matches an exclusion pattern."""
    relative = _relative_posix(path, root)
    parts = relative.split("/")

    candidates = [relative]
    candidates.extend("/".join(parts[:index]) for index in range(1, len(parts)))

    return any(
        _matches_exclusion(candidate, pattern) for candidate in candidates for pattern in patterns
    )


def discover(
    target: str,
    exclusions: list[str],
    max_file_bytes: int,
    *, include_secrets: bool = False,
) -> tuple[list[Path], int, list[str]]:
    """Discover supported files, returning files, skipped count, and warnings."""
    supported = is_secret_candidate if include_secrets else is_supported
    root = Path(target)

    if not root.exists():
        raise ValueError(f"target does not exist: {target}")
    if root.is_symlink():
        raise ValueError("scanning a symlink target is not supported")

    if root.is_file():
        if _excluded(root, root.parent, exclusions):
            return [], 1, []
        if not supported(root):
            return [], 1, [f"unsupported file type skipped: {root}"]
        try:
            if root.stat().st_size > max_file_bytes:
                return [], 1, [f"file exceeds max_file_bytes and was skipped: {root}"]
        except OSError as exc:
            return [], 1, [f"could not inspect {root}: {exc}"]
        return [root], 0, []

    if not root.is_dir():
        raise ValueError(f"target is neither a regular file nor a directory: {target}")

    files: list[Path] = []
    skipped = 0
    warnings: list[str] = []
    resolved_root = root.resolve()

    try:
        candidates = root.rglob("*")
        for candidate in candidates:
            try:
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

                if not supported(candidate):
                    continue

                if not candidate.resolve().is_relative_to(resolved_root):
                    skipped += 1
                    warnings.append(f"file outside scan root skipped: {candidate}")
                    continue

                if candidate.stat().st_size > max_file_bytes:
                    skipped += 1
                    warnings.append(f"file exceeds max_file_bytes and was skipped: {candidate}")
                    continue

                files.append(candidate)

            except OSError as exc:
                skipped += 1
                warnings.append(f"could not inspect {candidate}: {exc}")

    except OSError as exc:
        raise ValueError(f"could not discover files under {root}: {exc}") from exc

    return sorted(files), skipped, warnings
