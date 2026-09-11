from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
ALLOWED_CRITICALITY = {"low", "medium", "high", "critical"}
ALLOWED_FEATURES = {
    "script_interpreter", "process_injection", "autostart_change",
    "credential_access", "external_communication", "tool_transfer",
    "packed_content", "unsigned_binary", "macro_execution"
}


@dataclass(frozen=True)
class Sample:
    sample_id: str
    sha256: str
    file_name: str
    file_type: str
    host: str
    asset_criticality: str
    privileged_context: bool
    features: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.sample_id.strip():
            raise ValueError("sample_id is required")
        if not SHA256_RE.fullmatch(self.sha256):
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
        if self.asset_criticality not in ALLOWED_CRITICALITY:
            raise ValueError("unsupported asset_criticality")
        unknown = set(self.features) - ALLOWED_FEATURES
        if unknown:
            raise ValueError(f"unsupported feature(s): {sorted(unknown)}")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    sample_id: str
    title: str
    score: int
    priority: str
    observed_features: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    rationale: tuple[str, ...]
    remediation: str


def deterministic_id(sample_id: str, features: tuple[str, ...]) -> str:
    material = f"{sample_id}|{'|'.join(sorted(features))}".encode()
    return "IR-" + sha256(material).hexdigest()[:12].upper()
