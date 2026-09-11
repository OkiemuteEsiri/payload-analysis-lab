from __future__ import annotations
import argparse
from pathlib import Path
from .analyzer import analyze_all, load_samples
from .report import render


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline defensive analysis of synthetic artifact metadata")
    sub = parser.add_subparsers(dest="command", required=True)
    assess = sub.add_parser("assess")
    assess.add_argument("input")
    assess.add_argument("--output")
    args = parser.parse_args()
    findings = analyze_all(load_samples(args.input))
    report = render(findings)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
