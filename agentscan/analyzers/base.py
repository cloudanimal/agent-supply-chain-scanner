"""Analyzer interface.

Each analyzer owns one agent *surface* (skill, mcp, hook, memory, script,
prompt). The engine routes every file to exactly one analyzer via match(),
then calls analyze(). Analyzers reuse the shared deterministic detectors and
add structure-aware checks specific to their surface.
"""
from __future__ import annotations

from typing import List

from ..core.detect import scan_text
from ..core.finding import Finding


class Analyzer:
    surface: str = "prompt"

    def match(self, path: str, text: str) -> bool:
        raise NotImplementedError

    def analyze(self, path: str, text: str) -> List[Finding]:
        # Default: run the shared text detectors for this surface.
        return scan_text(text, path, self.surface)
