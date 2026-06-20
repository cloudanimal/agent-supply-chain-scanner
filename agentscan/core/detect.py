"""Shared detection primitives used by every analyzer.

Two layers:
  * run_rules()      — applies the declarative regex rules (rules.py).
  * hidden_content() — structural detectors for things regex-on-words misses:
                       invisible characters, Unicode-tag "ASCII smuggling",
                       mixed-script homoglyphs, and instruction-bearing HTML
                       comments. These are the techniques used to slip text
                       past a human reviewer while the model still reads it.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Iterable, List

from .finding import Finding, Severity
from .rules import Rule, all_rules

# Invisible / bidi / formatting characters that have no business in instructions.
_ZERO_WIDTH = re.compile(
    "[​‌‍‎‏‪‫‬‭‮"
    "⁠⁡⁢⁣⁤⁪⁫⁬⁭⁮⁯﻿]"
)
# Unicode "tag" block — invisible, can encode full ASCII payloads (ASCII smuggling).
_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")
# Cyrillic letters that look identical to Latin (а е о р с х …).
_CYRILLIC = re.compile("[Ѐ-ӿ]")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_INSTRUCTION_HINT = re.compile(
    r"\b(ignore|system|instruction|prompt|disregard|secret|exfiltrate|password|token)\b",
    re.IGNORECASE,
)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def run_rules(text: str, path: str, surface: str,
              rules: Iterable[Rule] | None = None) -> List[Finding]:
    """Apply every rule that targets this surface to `text`."""
    out: List[Finding] = []
    for rule in (rules if rules is not None else all_rules()):
        if not rule.applies_to(surface):
            continue
        for m in rule.pattern.finditer(text):
            ln = _line_of(text, m.start())
            snippet = text[m.start():m.end()].strip()
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                category=rule.category, surface=surface, path=path, line=ln,
                snippet=snippet[:200], rationale=rule.rationale,
                recommendation=rule.recommendation,
            ))
    return out


def hidden_content(text: str, path: str, surface: str) -> List[Finding]:
    """Structural detectors for content hidden from human reviewers."""
    out: List[Finding] = []

    for m in _ZERO_WIDTH.finditer(text):
        ch = m.group()
        out.append(Finding(
            "ASC050", "Invisible / bidi control character", Severity.HIGH,
            "obfuscation", surface, path, _line_of(text, m.start()),
            f"U+{ord(ch):04X} ({unicodedata.name(ch, 'unknown')})",
            "Zero-width or bidirectional control characters can hide or reorder "
            "text so a human sees something different from what the model parses.",
            "Strip non-printing characters from agent-facing instructions.",
        ))

    tags = _TAG_CHARS.findall(text)
    if tags:
        decoded = "".join(chr(ord(c) - 0xE0000) for c in tags if 0xE0020 <= ord(c) <= 0xE007E)
        out.append(Finding(
            "ASC051", "Unicode-tag ASCII smuggling", Severity.CRITICAL,
            "obfuscation", surface, path, 1,
            (decoded[:120] or f"{len(tags)} tag chars"),
            "Unicode tag characters are invisible but decode to ASCII, letting an "
            "attacker embed an entire hidden instruction the reviewer cannot see.",
            "Reject any instruction file containing U+E0000–U+E007F characters.",
        ))

    # Homoglyph: a token that mixes Latin and Cyrillic is almost always spoofing.
    for m in re.finditer(r"\b\w+\b", text):
        word = m.group()
        if _CYRILLIC.search(word) and re.search(r"[A-Za-z]", word):
            out.append(Finding(
                "ASC052", "Mixed-script homoglyph token", Severity.MEDIUM,
                "obfuscation", surface, path, _line_of(text, m.start()),
                word[:80],
                "A word mixing Latin and Cyrillic look-alike letters can spoof a "
                "trusted name (domain, command, package) past a human reader.",
                "Normalize to a single script and verify the intended token.",
            ))
            break  # one is enough to flag the file

    for m in _HTML_COMMENT.finditer(text):
        body = m.group(1)
        if _INSTRUCTION_HINT.search(body):
            out.append(Finding(
                "ASC053", "Instruction inside HTML comment", Severity.HIGH,
                "injection", surface, path, _line_of(text, m.start()),
                body.strip()[:160],
                "Markdown renders hide HTML comments from humans, but the model "
                "still reads them — a reliable place to smuggle instructions.",
                "Remove HTML comments from agent-loaded content or treat as untrusted.",
            ))

    return out


def scan_text(text: str, path: str, surface: str,
              rules: Iterable[Rule] | None = None) -> List[Finding]:
    """Full deterministic pass: declarative rules + hidden-content detectors."""
    return run_rules(text, path, surface, rules) + hidden_content(text, path, surface)
