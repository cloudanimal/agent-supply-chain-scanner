"""Reporters: human text, JSON, and SARIF 2.1.0 (for code-scanning UIs)."""
from __future__ import annotations

import json
from typing import List

from .engine import risk_score
from .finding import Finding, Severity

_COLOR = {
    Severity.CRITICAL: "\033[95m", Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m", Severity.LOW: "\033[96m", Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"


def _band(score: int) -> str:
    if score >= 60:
        return "CRITICAL"
    if score >= 30:
        return "ELEVATED"
    if score > 0:
        return "LOW"
    return "CLEAN"


def text_report(findings: List[Finding], color: bool = True) -> str:
    score = risk_score(findings)
    lines = [f"agentscan — risk {score}/100 ({_band(score)}), {len(findings)} finding(s)", ""]
    if not findings:
        lines.append("  No issues detected.")
        return "\n".join(lines)
    for f in findings:
        tag = f.severity.name
        if color:
            tag = f"{_COLOR[f.severity]}{tag:<8}{_RESET}"
        else:
            tag = f"{tag:<8}"
        loc = f"{f.path}:{f.line}" if f.line else f.path
        lines.append(f"  {tag} [{f.rule_id}] {f.title}  ({f.surface})")
        lines.append(f"           {loc}")
        if f.snippet:
            lines.append(f"           > {f.snippet}")
        lines.append(f"           {f.rationale}")
        lines.append(f"           fix: {f.recommendation}")
        lines.append("")
    return "\n".join(lines)


def json_report(findings: List[Finding]) -> str:
    return json.dumps({
        "tool": "agentscan",
        "risk_score": risk_score(findings),
        "band": _band(risk_score(findings)),
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


def sarif_report(findings: List[Finding]) -> str:
    rule_ids = {}
    rules = []
    for f in findings:
        if f.rule_id not in rule_ids:
            rule_ids[f.rule_id] = True
            rules.append({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.rationale},
                "helpUri": "https://github.com/cloudanimal/agent-supply-chain-scanner",
                "properties": {"category": f.category, "surface": f.surface},
            })
    results = [{
        "ruleId": f.rule_id,
        "level": f.sarif_level,
        "message": {"text": f"{f.rationale} Fix: {f.recommendation}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.path},
            "region": {"startLine": max(1, f.line)},
        }}],
    } for f in findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agentscan",
                "informationUri": "https://github.com/cloudanimal/agent-supply-chain-scanner",
                "rules": rules,
            }},
            "results": results,
        }],
    }, indent=2)


REPORTERS = {"text": text_report, "json": json_report, "sarif": sarif_report}
