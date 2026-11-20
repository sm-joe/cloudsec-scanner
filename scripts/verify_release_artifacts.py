"""Verify wheel/source license and metadata, and candidate checksums."""
from pathlib import Path
import hashlib
import tarfile
import zipfile
from email.parser import BytesParser


def verify(dist, license_path):
    dist = Path(dist)
    expected = Path(license_path).read_bytes()
    wheels = list(dist.glob("*.whl"))
    sources = list(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise ValueError("expected exactly one wheel and one source archive")
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        licenses = [name for name in names if name.endswith(".dist-info/licenses/LICENSE")]
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(licenses) != 1 or archive.read(licenses[0]) != expected:
            raise ValueError("wheel license missing or inconsistent")
        if len(metadata) != 1:
            raise ValueError("wheel metadata missing")
        validate_metadata(archive.read(metadata[0]))
    with tarfile.open(sources[0], "r:gz") as archive:
        names = archive.getnames()
        licenses = [name for name in names if name.count("/") == 1 and name.endswith("/LICENSE")]
        metadata = [name for name in names if name.count("/") == 1 and name.endswith("/PKG-INFO")]
        if len(licenses) != 1 or archive.extractfile(licenses[0]).read() != expected:
            raise ValueError("source license missing or inconsistent")
        if len(metadata) != 1:
            raise ValueError("source metadata missing")
        validate_metadata(archive.extractfile(metadata[0]).read())
    expected_names = {wheels[0].name, sources[0].name, "runtime-sbom.json"}
    seen = set()
    for line in (dist / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        if name not in expected_names or name in seen:
            raise ValueError("unexpected or duplicate checksum entry")
        seen.add(name)
        with (dist / name).open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError("checksum mismatch")
    if seen != expected_names:
        raise ValueError("incomplete checksum manifest")


def validate_metadata(raw):
    metadata = BytesParser().parsebytes(raw)
    if metadata.get("License-Expression") != "Apache-2.0" or "LICENSE" not in metadata.get_all("License-File", []):
        raise ValueError("missing SPDX license metadata")


if __name__ == "__main__":
    verify("dist", "LICENSE")
