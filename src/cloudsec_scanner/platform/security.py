"""Explicit operator-provisioned API tokens and restricted scan targets."""
import hmac
import json
import re
from pathlib import Path


def load_tokens(raw: str):
    try:
        tokens = json.loads(raw)
    except ValueError as exc:
        raise ValueError("invalid platform token configuration") from exc
    if not isinstance(tokens, dict) or not tokens:
        raise ValueError("at least one explicit platform token is required")
    if any(not isinstance(token, str) or len(token) < 32 or not isinstance(owner, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", owner) for token, owner in tokens.items()):
        raise ValueError("invalid platform token or principal")
    return tokens


def authenticate(tokens, credential):
    if not isinstance(credential, str):
        return None
    for token, owner in tokens.items():
        if hmac.compare_digest(token.encode(), credential.encode()):
            return owner
    return None


def resolve_target(root: Path, relative: str):
    if root.is_symlink():
        raise ValueError("symlink workspace is not allowed")
    path = Path(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts or "\\" in relative:
        raise ValueError("target must be a relative path within the workspace")
    cursor = root
    for part in path.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("symlink targets are not allowed")
    resolved = cursor.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve()) or not (resolved.is_dir() or resolved.is_file()):
        raise ValueError("invalid workspace target")
    return resolved
