"""Per-surface analyzers.

Kept in one module so the full surface coverage is readable at a glance; each
class is small. Order matters: the engine asks each analyzer (in REGISTRY
order) whether it matches a file, and the first match wins. Specific surfaces
(MCP, hooks, skill, memory, script) come before the generic prompt fallback.
"""
from __future__ import annotations

import json
import os
import re
from typing import List

from ..core.detect import scan_text
from ..core.finding import Finding, Severity
from .base import Analyzer

# Strings that look like real secrets if found inline in config.
_SECRET = re.compile(
    r"(AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}"
    r"|sk-[0-9A-Za-z]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
)
_RISKY_CMD = re.compile(r"\b(sh|bash|zsh)\b\s+-c\b|\b(node|python3?|deno)\b\s+-e\b|\bnc\b|\beval\b|curl[^\n]*\|\s*sh")


def _name(path: str) -> str:
    return os.path.basename(path).lower()


def _try_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


class MCPAnalyzer(Analyzer):
    surface = "mcp"

    def match(self, path: str, text: str) -> bool:
        n = _name(path)
        if "mcp" in n and n.endswith(".json"):
            return True
        data = _try_json(text)
        return isinstance(data, dict) and "mcpServers" in data

    def analyze(self, path: str, text: str) -> List[Finding]:
        out = scan_text(text, path, self.surface)
        data = _try_json(text) or {}
        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict):
            return out
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            cmd = " ".join([str(cfg.get("command", ""))] + [str(a) for a in cfg.get("args", []) or []])
            if _RISKY_CMD.search(cmd):
                out.append(Finding(
                    "ASC071", "MCP server runs an inline shell/eval command",
                    Severity.HIGH, "supply-chain", self.surface, path, 0,
                    f"{name}: {cmd[:120]}",
                    "The server entrypoint executes arbitrary inline code rather than a "
                    "pinned binary, so its behavior cannot be reviewed or trusted.",
                    "Run MCP servers from a pinned, inspectable executable, not sh -c/eval.",
                ))
            env = cfg.get("env", {}) or {}
            for k, v in env.items():
                if isinstance(v, str) and _SECRET.search(v):
                    out.append(Finding(
                        "ASC070", "Inlined secret in MCP env", Severity.HIGH,
                        "credential-access", self.surface, path, 0,
                        f"{name}.env.{k}",
                        "A live-looking credential is hardcoded in the server config; "
                        "it will leak with the file and is hard to rotate.",
                        "Reference secrets from the environment/secret store, never inline.",
                    ))
            url = str(cfg.get("url", "") or cfg.get("baseUrl", ""))
            if url.startswith("http://"):
                out.append(Finding(
                    "ASC073", "MCP server over cleartext HTTP", Severity.MEDIUM,
                    "supply-chain", self.surface, path, 0, url[:120],
                    "Cleartext transport lets a network attacker tamper with tool "
                    "definitions and responses the agent will trust.",
                    "Use HTTPS for remote MCP servers.",
                ))
        return out


class HookAnalyzer(Analyzer):
    surface = "hook"

    def match(self, path: str, text: str) -> bool:
        n = _name(path)
        if n in ("settings.json", "settings.local.json"):
            return True
        data = _try_json(text)
        return isinstance(data, dict) and ("hooks" in data or "permissions" in data)

    def analyze(self, path: str, text: str) -> List[Finding]:
        out = scan_text(text, path, self.surface)
        data = _try_json(text)
        if not isinstance(data, dict):
            return out
        # Hooks run shell automatically on events — high-value persistence spot.
        blob = json.dumps(data.get("hooks", {}))
        if _RISKY_CMD.search(blob) or re.search(r"curl|wget|nc |/dev/tcp", blob):
            out.append(Finding(
                "ASC080", "Hook executes network/shell command", Severity.HIGH,
                "persistence", self.surface, path, 0, blob[:160],
                "Hooks fire automatically on agent events; a network or shell hook is "
                "a reliable persistence and exfiltration mechanism.",
                "Restrict hooks to vetted local commands; review every hook addition.",
            ))
        perms = data.get("permissions", {})
        allow = json.dumps(perms.get("allow", perms if isinstance(perms, list) else []))
        if re.search(r'"(\*|Bash\(\*\)|.*:\*)"', allow):
            out.append(Finding(
                "ASC081", "Over-broad permission allow-rule", Severity.MEDIUM,
                "privilege", self.surface, path, 0, allow[:160],
                "A wildcard allow-rule removes the human checkpoint on dangerous tools.",
                "Grant least-privilege, specific permissions instead of wildcards.",
            ))
        if re.search(r'"(disableSandbox|dangerouslySkip\w*)"\s*:\s*true', text):
            out.append(Finding(
                "ASC082", "Sandbox/safety explicitly disabled", Severity.HIGH,
                "evasion", self.surface, path, 0, "disableSandbox / dangerouslySkip",
                "Turns off the isolation that bounds untrusted instructions.",
                "Keep the sandbox on; never ship config that disables it.",
            ))
        return out


class SkillAnalyzer(Analyzer):
    surface = "skill"

    def match(self, path: str, text: str) -> bool:
        n = _name(path)
        return n == "skill.md" or "/skills/" in path.replace("\\", "/").lower()

    def analyze(self, path: str, text: str) -> List[Finding]:
        out = scan_text(text, path, self.surface)
        # Flag references to bundled executable files; the engine will also scan
        # them directly if present, but the pointer itself is worth noting.
        for m in re.finditer(r"\]\(([^)]+\.(?:sh|py|js|ts|rb|ps1))\)|`([^`]+\.(?:sh|py|js|ts|rb|ps1))`", text):
            ref = m.group(1) or m.group(2)
            out.append(Finding(
                "ASC090", "Skill references a bundled script", Severity.INFO,
                "supply-chain", self.surface, path, text.count("\n", 0, m.start()) + 1,
                ref[:120],
                "A clean-looking SKILL.md can delegate the malicious behavior to a "
                "bundled script; the script is the real trust boundary.",
                "Ensure bundled scripts are scanned and reviewed alongside the skill.",
            ))
        return out


class MemoryAnalyzer(Analyzer):
    surface = "memory"

    def match(self, path: str, text: str) -> bool:
        n = _name(path)
        return n in ("claude.md", "agents.md", "memory.md", ".cursorrules", ".windsurfrules", "copilot-instructions.md")

    # Default analyze() (shared detectors) is the right behavior here: memory
    # files are prose auto-loaded into context, so injection/hidden-content
    # detection is exactly what matters.


class ScriptAnalyzer(Analyzer):
    surface = "script"

    _EXT = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".ts", ".rb", ".ps1")

    def match(self, path: str, text: str) -> bool:
        return _name(path).endswith(self._EXT)


class PromptAnalyzer(Analyzer):
    """Generic fallback: any markdown/text instruction file."""
    surface = "prompt"

    def match(self, path: str, text: str) -> bool:
        return _name(path).endswith((".md", ".markdown", ".txt", ".mdx", ".prompt"))


# First match wins; specific surfaces before the generic fallback.
REGISTRY = [
    MCPAnalyzer(),
    HookAnalyzer(),
    SkillAnalyzer(),
    MemoryAnalyzer(),
    ScriptAnalyzer(),
    PromptAnalyzer(),
]
