"""agentscan command-line interface."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List

from .analyzers.surfaces import REGISTRY
from .core import judge as judge_mod
from .core.engine import iter_files, risk_score, scan_path
from .core.finding import Finding, Severity
from .core.report import REPORTERS


def _add_llm_findings(root: str, model: str) -> List[Finding]:
    extra: List[Finding] = []
    for path in iter_files(root):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeError):
            continue
        for analyzer in REGISTRY:
            if analyzer.match(path, text):
                extra.extend(judge_mod.judge(text, path, analyzer.surface, model))
                break
    return extra


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="agentscan",
        description="Scan AI agent supply-chain artifacts (skills, MCP servers, "
                    "hooks, memory, prompts) for malicious or unsafe instructions.")
    p.add_argument("path", help="File or directory to scan")
    p.add_argument("-f", "--format", choices=sorted(REPORTERS), default="text")
    p.add_argument("--min-severity", default="INFO",
                   help="Hide findings below this severity (default INFO)")
    p.add_argument("--fail-on", default="HIGH",
                   help="Exit non-zero if any finding is at/above this severity "
                        "(default HIGH); use NONE to never fail")
    p.add_argument("--llm", action="store_true",
                   help="Add a Claude-as-judge pass (needs ANTHROPIC_API_KEY)")
    p.add_argument("--model", default="claude-haiku-4-5",
                   help="Model for the --llm pass")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"agentscan: path not found: {args.path}", file=sys.stderr)
        return 2

    try:
        min_sev = Severity.parse(args.min_severity)
    except ValueError as e:
        print(f"agentscan: {e}", file=sys.stderr)
        return 2

    findings = scan_path(args.path)

    if args.llm:
        if not judge_mod.available():
            print("agentscan: --llm set but ANTHROPIC_API_KEY is not set; "
                  "running rules-only.", file=sys.stderr)
        else:
            findings.extend(_add_llm_findings(args.path, args.model))
            findings.sort(key=lambda f: (-f.severity, f.path, f.line))

    findings = [f for f in findings if f.severity >= min_sev]

    reporter = REPORTERS[args.format]
    if args.format == "text":
        print(reporter(findings, color=not args.no_color and sys.stdout.isatty()))
    else:
        print(reporter(findings))

    if args.fail_on.upper() == "NONE":
        return 0
    try:
        gate = Severity.parse(args.fail_on)
    except ValueError as e:
        print(f"agentscan: {e}", file=sys.stderr)
        return 2
    return 1 if any(f.severity >= gate for f in findings) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
