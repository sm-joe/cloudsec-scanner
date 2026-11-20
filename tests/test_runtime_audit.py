import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("runtime_requirements", Path(__file__).resolve().parents[1] / "scripts/runtime_requirements.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_runtime_exact_versions():
    assert module.requirements([{"name": "cloudsec-scanner", "version": "0.1.0"}, {"name": "PyYAML", "version": "6.0.3"}, {"name": "pip", "version": "26.1"}]) == ["pip==26.1", "pyyaml==6.0.3"]


@pytest.mark.parametrize("document", [[], [{}], [{"name": "a\nother", "version": "1"}], [{"name": "x", "version": ">=1"}], [{"name": "x_y", "version": "1"}, {"name": "x-y", "version": "2"}]])
def test_bad_inventory_rejected(document):
    with pytest.raises(ValueError):
        module.requirements(document)
