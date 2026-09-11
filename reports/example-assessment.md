# Example Synthetic Payload Analysis

> Portfolio example only. All samples, hosts, hashes, and evidence are fictional and non-executable.

## Executive Summary

The synthetic triage set demonstrates four distinct response priorities. The most significant scenario combines process-injection metadata, credential-access indicators, external communication, an unsigned artifact, a high-criticality asset, and privileged context. This combination should receive immediate analyst attention even though no single metadata feature is treated as proof of compromise.

## Priority Observations

| Sample | Key signals | Expected priority |
|---|---|---|
| SYN-001 | process injection, credential access, external communications, privileged context | Critical |
| SYN-003 | packed content, transfer behavior, external communications | Medium/High depending on score |
| SYN-002 | script interpreter plus autostart change | Medium |
| SYN-004 | macro execution on low-criticality training endpoint | Low/Medium |

## Response Workflow

1. Preserve the original evidence and case metadata.
2. Validate endpoint and user context.
3. Correlate with EDR, identity, DNS/proxy, and change-management evidence where available.
4. Contain proportionately; avoid declaring compromise solely from static indicators.
5. Remediate the artifact and the enabling control gap.
6. Re-check the endpoint and verify post-change telemetry.
7. Close only when validation evidence is complete.

## ATT&CK Context

The example may produce mappings to T1055, T1003, T1071, T1059, T1547, and T1105. These mappings are investigative context only.
