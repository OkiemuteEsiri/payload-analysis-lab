from __future__ import annotations
from .analyzer import metrics
from .models import Finding


def render(findings: list[Finding]) -> str:
    m = metrics(findings)
    lines = [
        "# Synthetic Payload Analysis Assessment", "",
        "> Defensive analysis of fictional, non-executable evidence only.", "",
        "## Executive Summary", "",
        f"Total findings: **{m['total']}** | Critical: **{m['critical']}** | High: **{m['high']}** | Medium: **{m['medium']}** | Low: **{m['low']}**", "",
        "## Prioritized Findings", "",
        "| Finding | Sample | Score | Priority | ATT&CK |", "|---|---|---:|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f.finding_id} | {f.sample_id} | {f.score} | {f.priority} | {', '.join(f.attack_techniques) or 'n/a'} |")
    for f in findings:
        lines += ["", f"### {f.finding_id} — {f.title}", "", f"**Risk:** {f.score}/100 ({f.priority})", "", f"**Observed features:** {', '.join(f.observed_features)}", "", "**Rationale:**", *[f"- {r}" for r in f.rationale], "", f"**Remediation:** {f.remediation}"]
    lines += ["", "## Validation Requirement", "", "Do not close a finding solely because a file was removed. Require an approved change reference, endpoint re-check, and clean post-change telemetry.", ""]
    return "\n".join(lines)
