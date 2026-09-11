from __future__ import annotations

import json
from pathlib import Path
from .models import Finding, Sample, deterministic_id

ATTACK_MAP = {
    "script_interpreter": "T1059",
    "process_injection": "T1055",
    "autostart_change": "T1547",
    "credential_access": "T1003",
    "external_communication": "T1071",
    "tool_transfer": "T1105",
}
WEIGHTS = {
    "script_interpreter": 12,
    "process_injection": 30,
    "autostart_change": 18,
    "credential_access": 30,
    "external_communication": 18,
    "tool_transfer": 12,
    "packed_content": 8,
    "unsigned_binary": 8,
    "macro_execution": 14,
}
CRITICALITY = {"low": 0, "medium": 5, "high": 10, "critical": 15}


def load_samples(path: str | Path) -> list[Sample]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("top-level JSON must be a list")
    samples: list[Sample] = []
    seen: set[str] = set()
    required = {"sample_id", "sha256", "file_name", "file_type", "host", "asset_criticality", "privileged_context", "features"}
    for row in raw:
        if not isinstance(row, dict) or not required.issubset(row):
            raise ValueError("sample record is missing required fields")
        if row["sample_id"] in seen:
            raise ValueError(f"duplicate sample_id: {row['sample_id']}")
        if not isinstance(row["privileged_context"], bool) or not isinstance(row["features"], list):
            raise ValueError("invalid field type")
        sample = Sample(
            sample_id=row["sample_id"], sha256=row["sha256"], file_name=row["file_name"],
            file_type=row["file_type"], host=row["host"], asset_criticality=row["asset_criticality"],
            privileged_context=row["privileged_context"], features=tuple(row["features"]),
        )
        seen.add(sample.sample_id)
        samples.append(sample)
    return samples


def priority(score: int) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 35: return "medium"
    return "low"


def analyze(sample: Sample) -> Finding:
    reasons: list[str] = []
    score = 5
    for feature in sample.features:
        weight = WEIGHTS[feature]
        score += weight
        reasons.append(f"{feature} +{weight}")
    score += CRITICALITY[sample.asset_criticality]
    if sample.asset_criticality in {"high", "critical"}:
        reasons.append(f"{sample.asset_criticality} asset +{CRITICALITY[sample.asset_criticality]}")
    if sample.privileged_context:
        score += 15
        reasons.append("privileged context +15")
    score = min(100, score)
    techniques = tuple(sorted({ATTACK_MAP[f] for f in sample.features if f in ATTACK_MAP}))
    return Finding(
        finding_id=deterministic_id(sample.sample_id, sample.features), sample_id=sample.sample_id,
        title=f"Suspicious static behavior in {sample.file_name}", score=score, priority=priority(score),
        observed_features=sample.features, attack_techniques=techniques, rationale=tuple(reasons),
        remediation="Preserve evidence, isolate the affected endpoint when warranted, remove confirmed malicious artifacts through approved change control, and validate with fresh telemetry before closure.",
    )


def analyze_all(samples: list[Sample]) -> list[Finding]:
    return sorted((analyze(s) for s in samples), key=lambda f: (-f.score, f.sample_id))


def metrics(findings: list[Finding]) -> dict[str, int]:
    result = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        result[finding.priority] += 1
    return result
