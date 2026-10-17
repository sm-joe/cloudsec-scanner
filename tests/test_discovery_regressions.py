import pytest

from cloudsec_scanner.discovery import discover


def test_excluded_directory_does_not_leak_supported_files(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "insecure.tf").write_text(
        'resource "aws_s3_bucket" "example" {\n  acl = "public-read"\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "app.tf").write_text(
        'resource "aws_s3_bucket" "app" {\n  acl = "private"\n}\n',
        encoding="utf-8",
    )

    files, skipped, warnings = discover(str(tmp_path), ["vendor/"], 1024 * 1024)

    assert [path.name for path in files] == ["app.tf"]
    assert skipped == 1
    assert warnings == []


@pytest.mark.parametrize("pattern", ["vendor/**", "vendor/*", "*.tf"])
def test_glob_exclusions_are_applied(tmp_path, pattern):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "module.tf").write_text("# fixture\n", encoding="utf-8")
    (tmp_path / "root.tf").write_text("# fixture\n", encoding="utf-8")

    files, _, _ = discover(str(tmp_path), [pattern], 1024 * 1024)

    if pattern == "*.tf":
        assert files == []
    else:
        assert [path.name for path in files] == ["root.tf"]


def test_default_style_exclusions_work_for_nested_paths(tmp_path):
    nested = tmp_path / ".git" / "objects"
    nested.mkdir(parents=True)
    (nested / "metadata.json").write_text("{}", encoding="utf-8")
    (tmp_path / "main.tf").write_text("# fixture\n", encoding="utf-8")

    files, skipped, warnings = discover(
        str(tmp_path),
        [".git/**", ".venv/**", "venv/**", "node_modules/**", "dist/**", "build/**"],
        1024 * 1024,
    )

    assert [path.name for path in files] == ["main.tf"]
    assert skipped == 1
    assert warnings == []


def test_oversized_file_is_skipped_with_warning(tmp_path):
    target = tmp_path / "large.tf"
    target.write_text("x" * 100, encoding="utf-8")

    files, skipped, warnings = discover(str(tmp_path), [], 10)

    assert files == []
    assert skipped == 1
    assert len(warnings) == 1
    assert "max_file_bytes" in warnings[0]
    assert "large.tf" in warnings[0]


def test_unsupported_file_is_not_scanned(tmp_path):
    (tmp_path / "notes.txt").write_text("not IaC", encoding="utf-8")
    (tmp_path / "main.tf").write_text("# supported", encoding="utf-8")

    files, skipped, warnings = discover(str(tmp_path), [], 1024)

    assert [path.name for path in files] == ["main.tf"]
    assert skipped == 0
    assert warnings == []


def test_single_unsupported_file_returns_warning(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("not IaC", encoding="utf-8")

    files, skipped, warnings = discover(str(target), [], 1024)

    assert files == []
    assert skipped == 1
    assert len(warnings) == 1
    assert "unsupported file type" in warnings[0]


def test_results_are_sorted_deterministically(tmp_path):
    for name in ("z.tf", "a.tf", "m.tf"):
        (tmp_path / name).write_text("# fixture", encoding="utf-8")

    files, _, _ = discover(str(tmp_path), [], 1024)

    assert [path.name for path in files] == ["a.tf", "m.tf", "z.tf"]


def test_missing_target_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="target does not exist"):
        discover(str(tmp_path / "missing"), [], 1024)


def test_symlink_target_is_rejected(tmp_path):
    actual = tmp_path / "actual.tf"
    actual.write_text("# fixture", encoding="utf-8")
    link = tmp_path / "link.tf"

    try:
        link.symlink_to(actual)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not permitted in this environment")

    with pytest.raises(ValueError, match="symlink target"):
        discover(str(link), [], 1024)


def test_symlink_inside_directory_is_skipped(tmp_path):
    actual = tmp_path / "actual.tf"
    actual.write_text("# fixture", encoding="utf-8")
    link = tmp_path / "linked.tf"

    try:
        link.symlink_to(actual)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not permitted in this environment")

    files, skipped, warnings = discover(str(tmp_path), [], 1024)

    assert [path.name for path in files] == ["actual.tf"]
    assert skipped == 1
    assert warnings == []
