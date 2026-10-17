"""Shared test isolation fixtures."""

import pytest


@pytest.fixture(autouse=True)
def isolate_cloudsec_history(tmp_path, monkeypatch):
    """Keep automatic scan history out of the developer's real user database."""
    monkeypatch.setenv("CLOUDSEC_HISTORY_DB", str(tmp_path / "cloudsec-test-history.db"))
