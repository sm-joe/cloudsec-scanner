"""Independent persistent queue worker; no user-supplied commands or credentials."""
import os
import time
from pathlib import Path

from cloudsec_scanner.config import load_config
from cloudsec_scanner.platform.security import resolve_target
from cloudsec_scanner.platform.store import claim_scan, finish_scan, initialize
from cloudsec_scanner.scanner import scan_target


def run_once(engine, workspace):
    row = claim_scan(engine)
    if row is None:
        return False
    try:
        target = resolve_target(Path(workspace) / row["owner"], row["target"])
        # Workspace must be provisioned by the trusted operator, read-only to API users.
        result = scan_target(str(target), load_config(None))
        report = result.to_dict()
        finish_scan(engine, row["id"], report=report)
    except Exception:
        finish_scan(engine, row["id"], error="worker scan failed")
    return True


def main():
    workspace = Path(os.environ.get("CLOUDSEC_WORKSPACE", "./workspace")).resolve(strict=True)
    engine = initialize(os.environ.get("CLOUDSEC_DATABASE_URL", "sqlite:///cloudsec-platform.db"))
    while True:
        if not run_once(engine, workspace):
            time.sleep(2)


if __name__ == "__main__":
    main()
