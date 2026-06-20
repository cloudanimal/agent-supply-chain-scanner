"""Core data model: severities and findings.

A Finding is the single unit of output for the whole tool. Every analyzer,
rule, and reporter speaks in Findings so the pipeline stays uniform.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Optional


class Severity(enum.IntEnum):
    """Ordered so findings sort and threshold-filter naturally."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {name!r}")

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


# SARIF only has error/warning/note/none; map our scale onto it.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    surface: str          # which agent surface this came from (skill, mcp, hook, ...)
    path: str
    line: int = 0
    snippet: str = ""
    rationale: str = ""
    recommendation: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def sarif_level(self) -> str:
        return _SARIF_LEVEL[self.severity]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d

    # Used for de-duplication when several analyzers touch the same file.
    def key(self) -> tuple:
        return (self.rule_id, self.path, self.line, self.snippet[:80])
