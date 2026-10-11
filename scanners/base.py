from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

SOURCE_NETWORK = "network"
SOURCE_CODE = "code"
SOURCE_CLOUD = "cloud"

ASSET_ALGORITHM = "algorithm"
ASSET_CERTIFICATE = "certificate"
ASSET_KEY = "related-crypto-material"
ASSET_PROTOCOL = "protocol"


@dataclass
class Finding:
    source: str
    asset_type: str
    algorithm: str
    location: str
    key_size: int | None = None
    mode: str | None = None
    primitive: str | None = None
    raw: str | None = None
    context: dict[str, Any] = field(default_factory=dict)
    risk_tier: str | None = None
    nist_migration: str | None = None
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def fingerprint(self) -> str:
        key = f"{self.source}|{self.asset_type}|{self.algorithm}|{self.key_size}|{self.mode}|{self.location}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


class BaseScanner(ABC):
    name: str = "base"
    source: str = ""
    extensions: tuple[str, ...] = ()

    def __init__(self, target: str | Path):
        self.target = Path(target)
        self.errors: list[str] = []

    def iter_files(self) -> Iterator[Path]:
        if self.target.is_file():
            yield self.target
            return
        for p in self.target.rglob("*"):
            if p.is_file() and (not self.extensions or p.suffix.lower() in self.extensions):
                if any(part in {".git", "node_modules", "venv", ".venv", "__pycache__"} for part in p.parts):
                    continue
                yield p

    @abstractmethod
    def scan_file(self, path: Path) -> Iterable[Finding]:
        ...

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for path in self.iter_files():
            try:
                for f in self.scan_file(path):
                    if f.fingerprint not in seen:
                        seen.add(f.fingerprint)
                        findings.append(f)
            except Exception as exc:
                self.errors.append(f"{path}: {exc}")
        return findings
