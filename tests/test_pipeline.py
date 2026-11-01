
import sys
import importlib.util
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

PATCH_PATH = (
    PROJECT_ROOT
    / "reports"
    / "patched_vulnerable_example_3.py"
)

spec = importlib.util.spec_from_file_location(
    "patched_example",
    PATCH_PATH,
)

if spec is None or spec.loader is None:
    raise ImportError(f"Could not load patched module: {PATCH_PATH}")

patched = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patched)


def test_patched_command_allows_safe_demo(capsys):
    patched.run_command("echo Hello")
    assert capsys.readouterr().out.strip() == "Hello"


def test_patched_command_rejects_arbitrary_command():
    with pytest.raises(ValueError):
        patched.run_command("whoami")


def test_patched_secret_uses_environment_variable(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test_secret")
    assert patched.get_secret() == "test_secret"


def test_patched_secret_rejects_missing_value(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("APPLICATION_SECRET", raising=False)

    with pytest.raises(RuntimeError):
        patched.get_secret()


def test_patched_file_access(tmp_path, monkeypatch):
    monkeypatch.setattr(patched, "SAFE_DIR", tmp_path)

    sample = tmp_path / "hello.txt"
    sample.write_text("Secure file", encoding="utf-8")

    assert patched.read_file("hello.txt") == "Secure file"


def test_patched_file_rejects_path_traversal(tmp_path, monkeypatch):
    monkeypatch.setattr(patched, "SAFE_DIR", tmp_path)

    with pytest.raises(PermissionError):
        patched.read_file("../outside.txt")
