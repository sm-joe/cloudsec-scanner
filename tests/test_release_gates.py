import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("wait_release_gates", Path(__file__).resolve().parents[1] / "scripts/wait_release_gates.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

SHA = "a" * 40

def run(**overrides):
    return {"head_sha": SHA, "event": "push", "head_branch": "main", "run_number": 1, "status": "completed", "conclusion": "success", **overrides}


@pytest.mark.parametrize("items, expected", [
    ([], "pending"),
    ([run(event="pull_request")], "pending"),
    ([run(head_sha="b" * 40)], "pending"),
    ([run(head_branch="dev")], "pending"),
    ([run(status="in_progress", conclusion=None)], "pending"),
    ([run(conclusion="failure")], "failure"),
    ([run(conclusion="cancelled")], "failure"),
    ([run()], "success"),
    ([run(), run(run_number=2, conclusion="failure")], "failure"),
])
def test_gate(items, expected):
    assert module.classify({"workflow_runs": items}, SHA) == expected
