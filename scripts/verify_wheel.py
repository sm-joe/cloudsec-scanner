"""Install and smoke-test the built wheel in a fresh virtual environment."""
import os
from pathlib import Path
import subprocess
import tempfile
import venv


def main():
    wheels = list(Path("dist").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("expected exactly one wheel")
    wheel = wheels[0].resolve()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        env = root / "venv"
        venv.EnvBuilder(with_pip=True).create(env)
        python = env / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        subprocess.run([str(python), "-m", "pip", "install", str(wheel)], check=True, cwd=root)
        subprocess.run([str(python), "-m", "cloudsec_scanner.cli", "--version"], check=True, cwd=root)
        source = root / "safe.tf"
        source.write_text('resource "aws_ebs_volume" "example" { encrypted = true }', encoding="utf-8")
        safe = subprocess.run([str(python), "-m", "cloudsec_scanner.cli", "scan", str(source), "--scanner", "iac", "--no-history", "--color", "never"], check=True, cwd=root, capture_output=True, text=True, encoding="utf-8", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        if "PASSED" not in safe.stdout or "\x1b" in safe.stdout:
            raise RuntimeError("wheel failed terminal report smoke test")
        source.write_text('resource "aws_ebs_volume" "example" { encrypted = false }', encoding="utf-8")
        result = subprocess.run([str(python), "-m", "cloudsec_scanner.cli", "scan", str(source), "--scanner", "iac", "--no-history"], cwd=root)
        if result.returncode != 1:
            raise RuntimeError("wheel failed security exit-code smoke test")


if __name__ == "__main__":
    main()
