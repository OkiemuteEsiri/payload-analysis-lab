# Payload Analysis Lab

Defensive incident-response and malware-triage portfolio project for analyzing **synthetic, non-executable artifacts**. The lab demonstrates safe static triage, indicator extraction, contextual risk scoring, MITRE ATT&CK mapping, evidence handling, remediation guidance, and repeatable validation without providing malware, exploit payloads, persistence mechanisms, credential theft, or command-and-control code.

## Problem Statement

Security teams often need to rapidly triage suspicious files and scripts while preserving evidence quality and avoiding premature conclusions. This project implements an offline analysis pipeline for structured synthetic samples so analysts can practice classification, prioritization, reporting, and control-validation workflows safely.

## Architecture

```text
Synthetic artifact metadata
        |
        v
+----------------------+      +---------------------+
| Schema validation    | ---> | Static triage      |
| / fail-closed ingest |      | & feature analysis |
+----------------------+      +---------------------+
                                      |
                                      v
                             +---------------------+
                             | Risk engine         |
                             | 0-100 explainable   |
                             +---------------------+
                                      |
                        +-------------+-------------+
                        |                           |
                        v                           v
               ATT&CK context             Evidence validation
                        |                           |
                        +-------------+-------------+
                                      v
                              Markdown report
```

## Security Controls Demonstrated

- strict offline ingestion of synthetic JSON evidence;
- duplicate sample and malformed-field rejection;
- SHA-256 indicator-format validation;
- deterministic finding identifiers;
- explainable 0-100 contextual risk scoring;
- static feature analysis for suspicious behavior indicators;
- MITRE ATT&CK contextual mapping;
- evidence-chain and remediation-validation workflow;
- executive and technical reporting;
- unit tests and least-privilege CI.

## Safe Scope

The repository deliberately excludes executable malware, shellcode, credential theft, persistence, lateral movement, ransomware logic, C2 implementations, exploit code, live detonation, production targeting, real credentials, or client/employer data. Sample hashes, paths, domains, users, and hosts are fictional.

## Project Structure

```text
src/
  models.py
  analyzer.py
  remediation_validator.py
  report.py
  cli.py
data/
  synthetic_samples.json
  remediation_evidence.json
docs/
  architecture-methodology.md
reports/
  example-assessment.md
tests/
  test_analyzer.py
.github/workflows/
  tests.yml
```

## Risk Model

The analyzer starts from a base severity derived from static behavioral indicators and adds bounded contextual modifiers for execution capability, credential-access signals, persistence signals, external communications, privilege context, and asset criticality. Scores are capped at 100 and classified as:

| Score | Priority |
|---:|---|
| 80-100 | Critical |
| 60-79 | High |
| 35-59 | Medium |
| 0-34 | Low |

The score is a triage aid, not a malware verdict.

## MITRE ATT&CK Context

Mappings are defensive threat-model references only. They do **not** claim that a real intrusion or technique execution occurred.

- T1059 — Command and Scripting Interpreter
- T1055 — Process Injection
- T1547 — Boot or Logon Autostart Execution
- T1003 — OS Credential Dumping
- T1071 — Application Layer Protocol
- T1105 — Ingress Tool Transfer

## Usage

```bash
python -m src.cli assess data/synthetic_samples.json --output report.md
python -m unittest discover -s tests -v
```

The CLI performs no network access and does not execute analyzed content.

## Analysis Workflow

1. Validate structured evidence and reject malformed/duplicate records.
2. Normalize sample metadata and static features.
3. Derive findings from observed indicators rather than filenames alone.
4. Calculate contextual risk and sort the triage queue.
5. Map relevant ATT&CK techniques for defensive investigation context.
6. Document containment/remediation expectations.
7. Require post-remediation evidence before closure.
8. Generate an analyst-readable Markdown report.

## Design Decisions

- **Offline by design:** no external reputation lookup or detonation is required.
- **Evidence first:** findings require explicit observed metadata/features.
- **Deterministic output:** the same evidence produces the same finding IDs and ordering.
- **Fail closed:** malformed evidence is rejected rather than silently normalized.
- **No malware generation:** the project models defensive analysis only.

## Limitations

This lab does not replace EDR telemetry, sandbox detonation, reverse engineering, memory forensics, YARA at scale, threat-intelligence enrichment, or production malware-analysis platforms. Synthetic feature labels are intentionally simplified for portfolio demonstration.

## Skills Demonstrated

Incident response, malware triage, security engineering, Python, evidence validation, ATT&CK mapping, risk prioritization, remediation validation, reporting, unit testing, and CI/CD security hygiene.

## Roadmap

- add synthetic PE/ELF document metadata adapters;
- add configurable scoring policy profiles;
- add STIX-compatible indicator export;
- add Sigma/YARA rule-quality validation without weaponized content;
- add case-level timeline correlation;
- add SARIF output for pipeline consumption.

## License

Educational defensive-security portfolio project. No confidential or production data is included.
