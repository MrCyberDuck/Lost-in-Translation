"""Run manifest: everything needed to reproduce a run (tool versions, images, engine settings)."""
from __future__ import annotations

import datetime as dt
import importlib.metadata as md
import json
import pathlib
import platform
import subprocess


def _git(args: list[str], cwd: str = ".") -> str | None:
    try:
        return subprocess.check_output(["git", *args], cwd=cwd, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:  # noqa: BLE001
        return None


def _containers() -> list[dict]:
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--filter", "name=lit-wave", "--format", "{{.Names}}\t{{.Image}}"],
            text=True, stderr=subprocess.DEVNULL)
    except Exception:  # noqa: BLE001
        return []
    rows = []
    for line in out.splitlines():
        name, image = line.split("\t")
        digest = None
        try:
            digest = subprocess.check_output(
                ["docker", "image", "inspect", image, "--format", "{{.Id}}"], text=True).strip()
        except Exception:  # noqa: BLE001
            pass
        rows.append({"container": name, "image": image, "image_id": digest})
    return rows


def packages() -> dict[str, str]:
    names = ["pySigma", "sigma-cli", "pySigma-backend-splunk", "pySigma-backend-elasticsearch",
             "pySigma-backend-opensearch", "pySigma-backend-kusto", "pySigma-backend-loki",
             "pySigma-backend-sqlite", "pySigma-pipeline-windows", "pySigma-pipeline-sysmon"]
    out = {}
    for n in names:
        try:
            out[n] = md.version(n)
        except md.PackageNotFoundError:
            out[n] = None
    return out


def build(run_id: str, engines: dict, extra: dict | None = None) -> dict:
    return {
        "run_id": run_id,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "repo_commit": _git(["rev-parse", "HEAD"]),
        "sigmahq_commit": _git(["rev-parse", "HEAD"], cwd="rules/sigma"),
        "sigmahq_tag": _git(["describe", "--tags", "--exact-match"], cwd="rules/sigma"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "packages": packages(),
        "containers": _containers(),
        "engines": engines,
        **(extra or {}),
    }


def write(path: pathlib.Path, manifest: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
