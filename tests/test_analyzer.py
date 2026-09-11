import json
import tempfile
import unittest
from pathlib import Path

from src.analyzer import analyze, analyze_all, load_samples, metrics, priority
from src.models import Sample, deterministic_id
from src.remediation_validator import RemediationEvidence, validate
from src.report import render


class AnalyzerTests(unittest.TestCase):
    def sample(self, **overrides):
        base = dict(sample_id="S1", sha256="a" * 64, file_name="sample.meta", file_type="metadata", host="LAB-1", asset_criticality="medium", privileged_context=False, features=("script_interpreter",))
        base.update(overrides)
        return Sample(**base)

    def test_deterministic_id(self):
        self.assertEqual(deterministic_id("S1", ("script_interpreter",)), deterministic_id("S1", ("script_interpreter",)))

    def test_score_is_bounded(self):
        s = self.sample(asset_criticality="critical", privileged_context=True, features=("process_injection", "credential_access", "external_communication", "autostart_change", "tool_transfer"))
        self.assertEqual(analyze(s).score, 100)

    def test_credential_access_increases_score(self):
        baseline = analyze(self.sample()).score
        elevated = analyze(self.sample(features=("script_interpreter", "credential_access"))).score
        self.assertGreater(elevated, baseline)

    def test_privileged_context_increases_score(self):
        self.assertGreater(analyze(self.sample(privileged_context=True)).score, analyze(self.sample()).score)

    def test_attack_mapping(self):
        finding = analyze(self.sample(features=("process_injection", "credential_access")))
        self.assertEqual(finding.attack_techniques, ("T1003", "T1055"))

    def test_priority_bands(self):
        self.assertEqual(priority(80), "critical")
        self.assertEqual(priority(60), "high")
        self.assertEqual(priority(35), "medium")
        self.assertEqual(priority(34), "low")

    def test_unknown_feature_rejected(self):
        with self.assertRaises(ValueError):
            self.sample(features=("unknown",))

    def test_bad_hash_rejected(self):
        with self.assertRaises(ValueError):
            self.sample(sha256="bad")

    def test_duplicate_ingest_rejected(self):
        row = {"sample_id":"S1","sha256":"a"*64,"file_name":"x","file_type":"meta","host":"LAB","asset_criticality":"low","privileged_context":False,"features":[]}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "samples.json"; p.write_text(json.dumps([row, row]), encoding="utf-8")
            with self.assertRaises(ValueError): load_samples(p)

    def test_prioritization_order(self):
        findings = analyze_all([self.sample(sample_id="LOW"), self.sample(sample_id="HIGH", features=("credential_access", "process_injection"))])
        self.assertEqual(findings[0].sample_id, "HIGH")

    def test_metrics(self):
        self.assertEqual(metrics([analyze(self.sample())])["total"], 1)

    def test_report_contains_finding(self):
        f = analyze(self.sample())
        self.assertIn(f.finding_id, render([f]))

    def test_validated_remediation(self):
        ev = RemediationEvidence("F1", "CHG-1", True, True, True, "verified")
        self.assertEqual(validate(ev), "validated")

    def test_invalid_closure(self):
        ev = RemediationEvidence("F1", "CHG-1", False, False, False, "not done")
        self.assertEqual(validate(ev), "invalid_closure")

    def test_missing_change_reference(self):
        ev = RemediationEvidence("F1", "", True, True, True, "verified")
        self.assertEqual(validate(ev), "needs_evidence")

if __name__ == "__main__": unittest.main()
