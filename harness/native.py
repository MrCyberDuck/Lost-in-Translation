"""Native Sigma engines: Chainsaw and Hayabusa.

Both read EVTX directly and evaluate Sigma themselves, without pySigma, so they are an
independent check on the reference evaluator.

Build (no prebuilt binaries are needed; see docs/phase2.md):

    git clone -b v2.18.0 https://github.com/WithSecureLabs/chainsaw && cargo build --release
    git clone -b v4.4.0 https://github.com/Yamato-Security/hayabusa && cargo +1.99 build --release
    git clone https://github.com/Yamato-Security/hayabusa-rules            # config folder
    git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter
    python sigma-to-hayabusa-converter.py -r rules/sigma -o <converted>    # production rules

Paths come from environment variables (LIT_CHAINSAW, LIT_CHAINSAW_MAPPING, LIT_HAYABUSA,
LIT_HAYABUSA_CONFIG, LIT_HAYABUSA_CONVERTED). Without them, the engines are looked up in the
repo's git-excluded .tools folder (the release zips, as on the Windows laptop), and then in the
cloud container's build folder /home/user/native.

Two configurations, matching the evaluator's (S36, S37):

* neutral: logsource is not applied. Chainsaw runs with its mapping minus the logsource
  preconditions; Hayabusa runs the original SigmaHQ rules with the channel filter off (-A -a).
* production: each engine's own logsource handling. Chainsaw uses its shipped mapping;
  Hayabusa runs the rules converted by sigma-to-hayabusa-converter (Channel/EventID added,
  plus derived variants for built-in Security 4688 and registry events).
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile

import yaml

NATIVE = pathlib.Path(os.environ.get("LIT_NATIVE", "/home/user/native"))
TOOLS = pathlib.Path(__file__).resolve().parent.parent / ".tools"  # repo-local tools (the laptop layout, git-excluded)


def _find(env: str, patterns: list[str], default: pathlib.Path, tools: pathlib.Path = TOOLS) -> pathlib.Path:
    """The environment variable if set, else the first file under .tools matching a pattern, else the default."""
    if os.environ.get(env):
        return pathlib.Path(os.environ[env])
    for pattern in patterns:
        hits = sorted(p for p in tools.glob(pattern) if p.is_file())
        if hits:
            return hits[0]
    return default


CHAINSAW = _find("LIT_CHAINSAW", ["chainsaw/chainsaw/chainsaw.exe", "chainsaw/chainsaw.exe",
                                  "chainsaw/chainsaw/chainsaw", "chainsaw/chainsaw"],
                 NATIVE / "chainsaw/target/release/chainsaw")


def _default_chainsaw_mapping() -> pathlib.Path:
    """Next to the binary (release zip layout) or two levels up (cargo build layout)."""
    name = pathlib.Path("mappings/sigma-event-logs-all.yml")
    for root in (CHAINSAW.parent, CHAINSAW.parent.parent.parent):
        if (root / name).exists():
            return root / name
    return NATIVE / "chainsaw" / name


CHAINSAW_MAPPING = pathlib.Path(os.environ.get("LIT_CHAINSAW_MAPPING") or _default_chainsaw_mapping())
HAYABUSA = _find("LIT_HAYABUSA", ["hayabusa/hayabusa*.exe", "hayabusa/hayabusa-*-lin-*", "hayabusa/hayabusa"],
                 NATIVE / "hayabusa/target/release/hayabusa")


def _default_hayabusa_config() -> pathlib.Path:
    """rules/config next to the binary (release zip layout), else the hayabusa-rules clone."""
    beside = HAYABUSA.parent / "rules" / "config"
    return beside if beside.is_dir() else NATIVE / "hayabusa-rules/config"


HAYABUSA_CONFIG = pathlib.Path(os.environ.get("LIT_HAYABUSA_CONFIG") or _default_hayabusa_config())
HAYABUSA_CONVERTED = pathlib.Path(os.environ.get("LIT_HAYABUSA_CONVERTED")
                                  or (TOOLS / "hayabusa-converted" if (TOOLS / "hayabusa-converted").is_dir()
                                      else NATIVE / "hayabusa-converted"))


def versions() -> dict:
    out = {}
    for name, exe, arg in (("chainsaw", CHAINSAW, "--version"), ("hayabusa", HAYABUSA, "help")):
        try:
            res = subprocess.run([str(exe), arg], capture_output=True, text=True, timeout=30)
            out[name] = (res.stdout or res.stderr).strip().splitlines()[0]
        except (OSError, IndexError, subprocess.SubprocessError) as exc:
            out[name] = f"unavailable: {exc}"
    return out


def _event_id(path: str, record_id, root: pathlib.Path) -> str:
    p = pathlib.Path(path)
    try:
        rel = p.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        rel = p.as_posix()
    return f"{rel}#{record_id}"


# --------------------------------------------------------------------------- rule folders


def link_rules(paths: list[pathlib.Path], dest: pathlib.Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for i, p in enumerate(paths):
        os.symlink(p.resolve(), dest / f"{i:05d}_{p.name}")


def converted_rules(rules: dict[str, pathlib.Path]) -> dict[str, list[tuple[pathlib.Path, str]]]:
    """Original rule id -> [(converted file, variant)], for `rules` = {id: original path}.

    The converter writes each output under the original file name and gives it a new id
    with `related: derived` pointing at the original. (SigmaHQ rules also use `derived`
    among themselves, so the id link alone is ambiguous; file name plus link is not.)
    Variant is the output folder: `sysmon` or `builtin` (Windows built-in logs). For a rule
    with both, the sysmon variant is like-for-like with the taxonomy appendix and the builtin
    one is an extra log source (Security 4688 for process_creation, 4657 for registry).
    """
    by_name: dict[str, list[pathlib.Path]] = {}
    for path in HAYABUSA_CONVERTED.rglob("*.yml"):
        by_name.setdefault(path.name, []).append(path)
    out: dict[str, list[tuple[pathlib.Path, str]]] = {}
    for rid, orig in rules.items():
        for path in by_name.get(orig.name, []):
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            linked = {str(r["id"]) for r in doc.get("related") or [] if r.get("type") == "derived"}
            if rid == str(doc.get("id")) or rid in linked:
                out.setdefault(rid, []).append((path, path.relative_to(HAYABUSA_CONVERTED).parts[0]))
    return out


# --------------------------------------------------------------------------- Chainsaw


def neutral_mapping(dest: pathlib.Path) -> pathlib.Path:
    """Chainsaw's mapping without logsource preconditions (and without title exclusions)."""
    doc = yaml.safe_load(CHAINSAW_MAPPING.read_text(encoding="utf-8"))
    doc.get("extensions", {}).pop("preconditions", None)
    doc["exclusions"] = []
    dest.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return dest


def run_chainsaw(rules: list[pathlib.Path], scan_dir: pathlib.Path, evtx_root: pathlib.Path,
                 config: str, work: pathlib.Path) -> list[dict]:
    """Detections as dicts {rule_id, event_id}."""
    rules_dir = work / "chainsaw_rules"
    shutil.rmtree(rules_dir, ignore_errors=True)
    link_rules(rules, rules_dir)
    mapping = neutral_mapping(work / "chainsaw_neutral.yml") if config == "neutral" else CHAINSAW_MAPPING
    out = work / f"chainsaw_{config}.json"
    cmd = [str(CHAINSAW), "hunt", str(scan_dir), "-s", str(rules_dir), "--mapping", str(mapping),
           "--extension", "evtx", "--json", "-q", "--skip-errors", "-o", str(out)]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    hits = []
    for det in json.loads(out.read_text(encoding="utf-8") or "[]"):
        doc = det["document"]
        system = doc["data"]["Event"]["System"]
        hits.append({"rule_id": str(det["id"]),
                     "event_id": _event_id(doc["path"], system.get("EventRecordID"), evtx_root)})
    return hits


def chainsaw_unloadable(rules: dict[str, pathlib.Path]) -> dict[str, str]:
    """Rule id -> Chainsaw's error, for rules that `chainsaw lint` cannot load."""
    from concurrent.futures import ThreadPoolExecutor

    def lint(item):
        rid, path = item
        res = subprocess.run([str(CHAINSAW), "lint", "--kind", "sigma", str(path)], capture_output=True, text=True)
        text = res.stdout + res.stderr
        if "Validated 1 detection rules out of 1" in text:
            return None
        err = next((l.split(":", 1)[-1].strip() for l in text.splitlines() if l.startswith("[!]")), "not loaded")
        return rid, err

    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(r for r in pool.map(lint, rules.items()) if r)


# --------------------------------------------------------------------------- Hayabusa


def _hayabusa_config(work: pathlib.Path) -> pathlib.Path:
    """Copy of the rules config with the exclude and noisy lists emptied, so every rule loads."""
    cfg = work / "hayabusa_config"
    shutil.rmtree(cfg, ignore_errors=True)
    shutil.copytree(HAYABUSA_CONFIG, cfg)
    for name in ("exclude_rules.txt", "noisy_rules.txt"):
        (cfg / name).write_text("", encoding="utf-8")
    return cfg


def run_hayabusa(rules: list[tuple[pathlib.Path, str, str]], scan_dir: pathlib.Path,
                 evtx_root: pathlib.Path, config: str, work: pathlib.Path) -> list[dict]:
    """`rules` = [(file, original rule id, variant)]. Detections as {rule_id, variant, event_id}."""
    rules_dir = work / f"hayabusa_rules_{config}"
    shutil.rmtree(rules_dir, ignore_errors=True)
    rules_dir.mkdir(parents=True)
    by_file_id: dict[str, tuple[str, str]] = {}
    for i, (path, orig, variant) in enumerate(rules):
        shutil.copyfile(path, rules_dir / f"{i:05d}_{variant}_{path.name}")  # Hayabusa skips symlinks
        rid = str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])
        by_file_id[rid] = (orig, variant)
    cfg = _hayabusa_config(work)
    out = work / f"hayabusa_{config}.jsonl"
    cmd = [str(HAYABUSA), "dfir-timeline", "-d", str(scan_dir.resolve()), "-r", str(rules_dir), "-c", str(cfg),
           "-w", "-q", "-K", "-N", "-Q", "-C", "-U", "-O", "-A", "-a", "-D", "-u", "-n",
           "-p", "verbose", "-t", "jsonl", "-o", str(out)]
    with tempfile.TemporaryDirectory() as cwd:  # Hayabusa resolves ./rules/config from the cwd
        (pathlib.Path(cwd) / "rules").mkdir()
        os.symlink(cfg, pathlib.Path(cwd) / "rules" / "config")
        subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=cwd)
    hits = []
    if not out.exists():
        return hits
    for line in out.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        det = json.loads(line)
        orig, variant = by_file_id.get(str(det.get("RuleID")), (str(det.get("RuleID")), "unknown"))
        hits.append({"rule_id": orig, "variant": variant,
                     "event_id": _event_id(det["EvtxFile"], det["RecordID"], evtx_root)})
    return hits
