"""Deterministic detection rules — the regex/heuristic heart of the scanner.

Rules are plain data so they're easy to read, audit, and extend. Each rule
declares which surfaces it applies to; the engine filters by surface before
running, so an MCP-only rule never fires on a prose prompt and vice versa.

Surfaces: "prompt", "skill", "mcp", "hook", "memory", "script", "*" (any).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern

from .finding import Severity

ANY = "*"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    pattern: Pattern
    rationale: str
    recommendation: str
    surfaces: tuple = (ANY,)

    def applies_to(self, surface: str) -> bool:
        return ANY in self.surfaces or surface in self.surfaces


def _r(pat: str) -> Pattern:
    return re.compile(pat, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Instruction override / role hijack
# ---------------------------------------------------------------------------
_RULES = [
    Rule("ASC001", "Instruction-override directive", Severity.HIGH, "injection",
         _r(r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(instruction|prompt|rule|message|context)s?"),
         "Classic prompt-injection phrasing that tries to override the agent's governing instructions.",
         "Treat as untrusted. Remove the override directive or quarantine the source."),

    Rule("ASC002", "System-prompt subversion", Severity.HIGH, "injection",
         _r(r"\b(your|the)\s+(system\s+prompt|guidelines|safety\s+(rules|guidelines)|instructions)\b[^.\n]{0,30}\b(do not apply|no longer apply|are void|are suspended|ignore)"),
         "Attempts to nullify the agent's system prompt or safety guidelines.",
         "Reject. Legitimate instructions do not ask the model to void its own guardrails."),

    Rule("ASC003", "Role reassignment", Severity.MEDIUM, "injection",
         _r(r"\b(from now on|going forward)\b[^.\n]{0,30}\byou\s+(are|will be|act as|must act as)\b"),
         "Reassigns the agent's role/persona, a common lead-in to jailbreaks.",
         "Verify the role change is intended by the skill author, not injected."),

    Rule("ASC004", "Covert-action directive", Severity.HIGH, "evasion",
         _r(r"\b(do not|don't|never)\b[^.\n]{0,25}\b(tell|inform|alert|notify|mention|reveal|disclose)\b[^.\n]{0,20}\b(the\s+)?(user|operator|human|owner)\b"),
         "Instructs the agent to hide its actions from the user — a hallmark of malicious instructions.",
         "Reject. The agent must never be told to conceal activity from its operator."),

    Rule("ASC005", "Silent / no-confirmation directive", Severity.MEDIUM, "evasion",
         _r(r"\b(silently|quietly|without\s+(asking|confirmation|telling|prompting|notifying))\b"),
         "Pushes the agent to act without the usual confirmation, defeating human-in-the-loop controls.",
         "Require explicit confirmation for outward-facing or destructive actions."),

    # -----------------------------------------------------------------------
    # Data exfiltration
    # -----------------------------------------------------------------------
    Rule("ASC010", "Outbound data POST", Severity.HIGH, "exfiltration",
         _r(r"\b(curl|wget|http[sx]?)\b[^\n]{0,80}(-d|--data|--data-binary|-T|--upload-file|-F)\b[^\n]{0,80}https?://"),
         "Sends local data to a remote endpoint — a direct exfiltration primitive.",
         "Confirm the destination is trusted and the payload contains no secrets/files."),

    Rule("ASC011", "Markdown-image exfiltration", Severity.HIGH, "exfiltration",
         _r(r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*(\{\{|\$\{|%7B|=)"),
         "Auto-rendered markdown image with a query string can silently leak context to an attacker URL.",
         "Strip remote images with dynamic query strings from agent-rendered content."),

    Rule("ASC012", "Known exfil / paste sink", Severity.HIGH, "exfiltration",
         _r(r"\b(webhook\.site|requestbin|pipedream\.net|\.ngrok\.(io|app)|pastebin\.com|hastebin|transfer\.sh|0x0\.st|burpcollaborator|oast\.(fun|live|site|pro))\b"),
         "References a service commonly used to receive exfiltrated data or out-of-band callbacks.",
         "Treat any agent instruction pointing at these sinks as hostile until proven otherwise."),

    Rule("ASC013", "Decode-and-execute", Severity.CRITICAL, "obfuscation",
         _r(r"\b(base64\s+(-d|--decode)|atob|fromCharCode|xxd\s+-r)\b[^\n]{0,60}(\|\s*(sh|bash|zsh|python|node|eval)|eval\()"),
         "Decodes an encoded blob and pipes it straight into an interpreter — classic payload hiding.",
         "Never execute decoded content. Inspect the decoded payload manually."),

    # -----------------------------------------------------------------------
    # Credential & secret access
    # -----------------------------------------------------------------------
    Rule("ASC020", "Sensitive credential path", Severity.HIGH, "credential-access",
         _r(r"(~|\$HOME|/root|/home/[^/\s]+)?/?\.(ssh/id_\w+|aws/credentials|netrc|git-credentials|npmrc|docker/config\.json)|/etc/shadow|id_rsa\b|\.pem\b"),
         "Reads files that hold private keys, cloud credentials, or tokens.",
         "Skills should not need raw credential material. Block and review."),

    Rule("ASC021", "Environment-variable harvest", Severity.MEDIUM, "credential-access",
         _r(r"\b(printenv|env\s*\||process\.env\b[^\n]{0,40}(post|fetch|send)|os\.environ\b[^\n]{0,40}(post|requests|urlopen))"),
         "Reads the full environment (often where API keys live) in proximity to a network call.",
         "Scope env access narrowly; never ship the whole environment off-box."),

    # -----------------------------------------------------------------------
    # Destructive actions
    # -----------------------------------------------------------------------
    Rule("ASC030", "Destructive filesystem command", Severity.HIGH, "destructive",
         _r(r"\brm\s+-[rf]{1,2}[a-z]*\s+(/|~|\$HOME|\*|\.\s|\.\.)"),
         "Recursive force-delete of high-value paths.",
         "Require explicit, scoped paths and human confirmation before any bulk delete."),

    Rule("ASC031", "History-rewriting / force git op", Severity.MEDIUM, "destructive",
         _r(r"\bgit\s+(push\s+(-f|--force)|reset\s+--hard\s+origin|clean\s+-[a-z]*f[a-z]*d)"),
         "Force-push or hard-reset can destroy others' work irreversibly.",
         "Disallow forced/destructive git operations from automated instructions."),

    Rule("ASC032", "Destructive database statement", Severity.HIGH, "destructive",
         _r(r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s*;)"),
         "Irreversible data-loss SQL.",
         "Gate schema/data destruction behind explicit human approval."),

    Rule("ASC033", "Pipe-to-shell install", Severity.HIGH, "destructive",
         _r(r"\b(curl|wget)\b[^\n]{0,120}\|\s*(sudo\s+)?(sh|bash|zsh)\b"),
         "Executes remote, unverified code with shell (often root) privileges.",
         "Download, inspect, and checksum scripts before running; never pipe to shell."),

    # -----------------------------------------------------------------------
    # Guardrail / safety bypass
    # -----------------------------------------------------------------------
    Rule("ASC040", "Guardrail-disable directive", Severity.HIGH, "evasion",
         _r(r"\b(disable|turn\s+off|bypass|skip|override)\b[^.\n]{0,25}\b(sandbox|safety|guardrail|confirmation|permission|approval|review|filter)s?\b"),
         "Tries to switch off the controls that keep the agent safe.",
         "Reject. Controls exist precisely to bound untrusted instructions."),

    Rule("ASC041", "Auto-approve escalation", Severity.HIGH, "privilege",
         _r(r"\b(auto[-\s]?approve|always\s+allow|grant\s+all|allow\s+all\s+(tools|commands|permissions)|dangerously)\b"),
         "Requests blanket approval, removing the human checkpoint on dangerous actions.",
         "Keep permissions least-privilege; never blanket-approve."),

    # -----------------------------------------------------------------------
    # Suspicious egress
    # -----------------------------------------------------------------------
    Rule("ASC060", "Raw-IP endpoint", Severity.LOW, "egress",
         _r(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?"),
         "Hardcoded IP endpoints evade domain reputation and are common in C2/exfil.",
         "Prefer named, allow-listed hosts; investigate raw-IP destinations."),

    Rule("ASC061", "URL shortener", Severity.LOW, "egress",
         _r(r"\bhttps?://(bit\.ly|t\.co|tinyurl\.com|goo\.gl|is\.gd|cutt\.ly|rb\.gy)/"),
         "Shorteners hide the true destination from review.",
         "Expand and verify shortened links before trusting them."),
]


def all_rules() -> list:
    return list(_RULES)
