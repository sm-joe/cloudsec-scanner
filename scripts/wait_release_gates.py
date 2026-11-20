"""Wait for exact main-push workflows without treating missing/failing gates as success."""
import json
import os
import re
import subprocess
import time

WORKFLOWS = ("cloudsec.yml", "portability.yml")


def classify(document, sha):
    runs = document.get("workflow_runs")
    if not isinstance(runs, list):
        raise ValueError("missing workflow runs")
    matches = [run for run in runs if run.get("head_sha") == sha and run.get("event") == "push" and run.get("head_branch") == "main"]
    if not matches:
        return "pending"
    newest = max(matches, key=lambda run: (run["run_number"], run.get("run_attempt", 1)))
    if newest.get("status") != "completed":
        return "pending"
    return "success" if newest.get("conclusion") == "success" else "failure"


def wait():
    repo, sha = os.environ["GH_REPO"], os.environ["RELEASE_SHA"]
    if repo != "sm-joe/cloudsec-scanner" or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("unexpected release repository or revision")
    for attempt in range(60):
        states = []
        for workflow in WORKFLOWS:
            raw = subprocess.check_output(["gh", "api", f"repos/{repo}/actions/workflows/{workflow}/runs?event=push&branch=main&head_sha={sha}&per_page=100"], timeout=30)
            states.append(classify(json.loads(raw), sha))
        print(f"Required release gates: {dict(zip(WORKFLOWS, states, strict=True))}", flush=True)
        if "failure" in states:
            raise RuntimeError("required release workflow failed")
        if all(state == "success" for state in states):
            return
        if attempt < 59:
            time.sleep(15)
    raise RuntimeError("required release workflows did not pass within deadline")


if __name__ == "__main__":
    wait()
