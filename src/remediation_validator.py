from __future__ import annotations

from dataclasses import dataclass

@dataclass(frozen=True)
class RemediationEvidence:
    finding_id: str
    change_reference: str
    artifact_removed: bool
    endpoint_rechecked: bool
    telemetry_clean: bool
    analyst_notes: str


def validate(evidence: RemediationEvidence) -> str:
    if not evidence.change_reference.strip() or not evidence.analyst_notes.strip():
        return "needs_evidence"
    if evidence.artifact_removed and evidence.endpoint_rechecked and evidence.telemetry_clean:
        return "validated"
    if evidence.artifact_removed and evidence.endpoint_rechecked:
        return "ready_for_validation"
    return "invalid_closure"
