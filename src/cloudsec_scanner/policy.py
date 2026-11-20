"""Explicit, narrowly scoped, expiring finding exceptions."""
from datetime import date, datetime, UTC
from pathlib import Path
import re

from cloudsec_scanner.safe_input import safe_yaml_documents
from cloudsec_scanner.comparison import finding_identity, _relative_finding


def load_exceptions(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("exception file exceeds size limit")
    docs = safe_yaml_documents(raw.decode("utf-8"))
    if len(docs) != 1 or not isinstance(docs[0], dict) or set(docs[0]) != {"version", "exceptions"} or type(docs[0]["version"]) is not int or docs[0]["version"] != 1:
        raise ValueError("invalid exception policy schema")
    entries = docs[0]["exceptions"]
    if not isinstance(entries, list) or len(entries) > 10000:
        raise ValueError("invalid exception list")
    seen = set()
    result = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"finding_id", "expires", "reason", "approved_by"}:
            raise ValueError("exception requires finding_id, expires, reason and approved_by")
        identity = entry["finding_id"]
        if not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{64}", identity) or identity in seen:
            raise ValueError("invalid or duplicate exception fingerprint")
        expires = entry["expires"]
        if isinstance(expires, str):
            expires = date.fromisoformat(expires)
        if type(expires) is not date:
            raise ValueError("exception expiry must be a calendar date")
        for key in ("reason", "approved_by"):
            value = entry[key]
            if not isinstance(value, str) or not value.strip() or len(value) > 512 or any(ord(c) < 32 for c in value):
                raise ValueError("invalid exception metadata")
        seen.add(identity)
        result.append({**entry, "expires": expires.isoformat()})
    return result


def apply_exceptions(result, exceptions, *, today=None):
    """Keep original findings and record accepted risk separately."""
    today = today or datetime.now(UTC).date()
    by_id = {entry["finding_id"]: entry for entry in exceptions}
    identities = [finding_identity(_relative_finding(f.to_dict(), {"target": result.target})) for f in result.findings]
    counts = {}
    for identity in identities:
        counts[identity] = counts.get(identity, 0) + 1
    active = []
    matched = set()
    for identity in sorted(set(identities)):
        entry = by_id.get(identity)
        if not entry:
            continue
        matched.add(identity)
        status = "EXPIRED" if date.fromisoformat(entry["expires"]) < today else "AMBIGUOUS" if counts[identity] != 1 else "ACCEPTED"
        result.exceptions.append({**entry, "status": status})
        if status == "ACCEPTED":
            active.append(identity)
    for identity, entry in by_id.items():
        if identity not in matched:
            result.exceptions.append({**entry, "status": "UNMATCHED"})
    return set(active)
