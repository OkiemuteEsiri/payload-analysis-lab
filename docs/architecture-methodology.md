# Architecture and Methodology

## Purpose

This lab demonstrates a defensive incident-response triage pipeline using synthetic, non-executable artifact metadata. It is designed to show analytical engineering, evidence discipline, prioritization, ATT&CK contextualization, remediation tracking, and validation without shipping malicious code.

## Trust Boundaries

1. **Evidence boundary:** JSON inputs are untrusted until schema and value validation completes.
2. **Analysis boundary:** only declared static features are evaluated; files are never executed.
3. **Reporting boundary:** scores communicate triage priority, not a malware verdict.
4. **Closure boundary:** remediation is not treated as complete until post-change evidence is present.

## Methodology

### 1. Evidence acquisition
Use exported metadata from an approved source. Preserve original evidence externally according to organizational forensic procedures. This repository intentionally models metadata only.

### 2. Validation
Reject malformed SHA-256 values, duplicate sample IDs, unsupported criticality labels, unsupported feature names, and invalid field types. Silent coercion is avoided.

### 3. Static triage
The analyzer considers interpreters, process injection indicators, autostart changes, credential-access indicators, external communications, transfer behavior, packing, signature state, and macro execution metadata.

### 4. Contextual risk
Risk combines behavior weights with asset criticality and privileged execution context. The output is capped at 100. The model is intentionally transparent so reviewers can challenge the weighting.

### 5. ATT&CK mapping
Relevant observed behaviors are mapped to ATT&CK for defensive investigation context: T1059, T1055, T1547, T1003, T1071, and T1105. A mapping means only that a behavior resembles technique context; it is not proof of adversary activity.

### 6. Response and remediation
Preserve evidence before removal. Apply containment proportionately, remove confirmed malicious artifacts through approved change control, address the enabling control gap, and document ownership.

### 7. Validation
Closure requires a change reference, evidence that the artifact/control state changed, an endpoint re-check, and clean post-change telemetry. Failed validation returns the item to remediation.

## Production Extensions

A production design would integrate EDR, sandboxing, file reputation, YARA/Sigma governance, case management, evidence hashing, analyst identity, immutable audit logs, and approval workflows. Those integrations are intentionally out of scope here.
