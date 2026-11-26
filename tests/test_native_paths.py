"""harness/native.py finds the engines from an environment variable, then the repo's .tools folder, then the default."""
import pathlib

from harness import native


def _touch(path: pathlib.Path) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("")
    return path


def test_env_variable_wins(tmp_path, monkeypatch):
    _touch(tmp_path / "chainsaw/chainsaw/chainsaw.exe")
    monkeypatch.setenv("LIT_CHAINSAW", "/opt/chainsaw")
    assert native._find("LIT_CHAINSAW", ["chainsaw/chainsaw/chainsaw.exe"], pathlib.Path("/d"), tmp_path) \
        == pathlib.Path("/opt/chainsaw")


def test_windows_release_layout_under_tools(tmp_path, monkeypatch):
    monkeypatch.delenv("LIT_CHAINSAW", raising=False)
    exe = _touch(tmp_path / "chainsaw/chainsaw/chainsaw.exe")
    _touch(tmp_path / "chainsaw/chainsaw/mappings/sigma-event-logs-all.yml")
    assert native._find("LIT_CHAINSAW", ["chainsaw/chainsaw/chainsaw.exe", "chainsaw/chainsaw"],
                        pathlib.Path("/d"), tmp_path) == exe


def test_hayabusa_versioned_exe_name(tmp_path, monkeypatch):
    monkeypatch.delenv("LIT_HAYABUSA", raising=False)
    exe = _touch(tmp_path / "hayabusa/hayabusa-4.4.0-win-x64.exe")
    (tmp_path / "hayabusa/rules/config").mkdir(parents=True)
    assert native._find("LIT_HAYABUSA", ["hayabusa/hayabusa*.exe", "hayabusa/hayabusa"], pathlib.Path("/d"),
                        tmp_path) == exe


def test_directories_are_not_binaries(tmp_path, monkeypatch):
    monkeypatch.delenv("LIT_CHAINSAW", raising=False)
    (tmp_path / "chainsaw/chainsaw").mkdir(parents=True)  # the release folder itself, not the binary
    assert native._find("LIT_CHAINSAW", ["chainsaw/chainsaw"], pathlib.Path("/d"), tmp_path) == pathlib.Path("/d")


def test_falls_back_to_default(tmp_path, monkeypatch):
    monkeypatch.delenv("LIT_CHAINSAW", raising=False)
    assert native._find("LIT_CHAINSAW", ["chainsaw/chainsaw.exe"], pathlib.Path("/d"), tmp_path) == pathlib.Path("/d")
