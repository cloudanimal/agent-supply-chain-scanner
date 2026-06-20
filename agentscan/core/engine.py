"""Scan orchestration: walk paths, route files to analyzers, collect findings."""
from __future__ import annotations

import os
from typing import List, Optional

from ..analyzers.surfaces import REGISTRY
from .finding import Finding, Severity

# Files we never read (binaries, vendored deps, vcs internals).
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
_MAX_BYTES = 2_000_000


def _read(path: str) -> Optional[str]:
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="strict") as fh:
            return fh.read()
    except (OSError, UnicodeError):
        return None  # unreadable or binary -> skip


def iter_files(root: str):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in sorted(filenames):
            yield os.path.join(dirpath, fn)


def scan_path(root: str) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for path in iter_files(root):
        text = _read(path)
        if text is None:
            continue
        for analyzer in REGISTRY:
            if analyzer.match(path, text):
                for f in analyzer.analyze(path, text):
                    if f.key() not in seen:
                        seen.add(f.key())
                        findings.append(f)
                break  # first matching analyzer owns the file
    findings.sort(key=lambda f: (-f.severity, f.path, f.line))
    return findings


def risk_score(findings: List[Finding]) -> int:
    """0–100 composite. Saturating weighted sum so one CRITICAL is loud but
    many lows can't quietly add up to a critical-looking score."""
    weight = {Severity.CRITICAL: 40, Severity.HIGH: 20,
              Severity.MEDIUM: 8, Severity.LOW: 3, Severity.INFO: 0}
    total = sum(weight[f.severity] for f in findings)
    return min(100, total)
