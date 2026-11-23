"""Engine endpoints. Defaults match compose/wave-a.yml and compose/wave-b.yml; override with env vars."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass
class Config:
    es_url: str = field(default_factory=lambda: _env("LIT_ES_URL", "http://127.0.0.1:9200"))
    os_url: str = field(default_factory=lambda: _env("LIT_OS_URL", "http://127.0.0.1:9201"))
    loki_url: str = field(default_factory=lambda: _env("LIT_LOKI_URL", "http://127.0.0.1:3100"))
    kusto_url: str = field(default_factory=lambda: _env("LIT_KUSTO_URL", "http://127.0.0.1:8080"))
    splunk_url: str = field(default_factory=lambda: _env("LIT_SPLUNK_URL", "https://127.0.0.1:8089"))
    splunk_hec_url: str = field(default_factory=lambda: _env("LIT_SPLUNK_HEC_URL", "https://127.0.0.1:8088"))
    splunk_user: str = field(default_factory=lambda: _env("LIT_SPLUNK_USER", "admin"))
    splunk_password: str = field(default_factory=lambda: _env("SPLUNK_PASSWORD", "ChangeMe-lit-2026"))
    sqlite_dir: str = field(default_factory=lambda: _env("LIT_SQLITE_DIR", "results/sqlite"))
