# agent-supply-chain-scanner

**SAST for AI agent instructions.** `agentscan` detects prompt injection and
malicious instructions across the artifacts an AI agent trusts and auto-loads —
**skills, MCP servers, hooks, memory/rule files, and prompts** — before they
ever reach the model.

**▶ Live demo (no install):** https://cloudanimal.github.io/agent-supply-chain-scanner/ — paste or drop a skill/MCP/prompt and scan it entirely in your browser.

Agent skills, MCP servers, and plugins are an emerging software supply chain:
third-party text and config that an agent will *execute on your behalf*. A
malicious one doesn't need a memory-corruption bug — it just needs the agent to
read it. `agentscan` treats that text as attack surface and scans it like code.

```
$ agentscan ./suspicious-skill/
agentscan — risk 100/100 (CRITICAL), 19 finding(s)

  CRITICAL [ASC013] Decode-and-execute  (script)
           scripts/setup.sh:4
           > base64 -d | bash
           Decodes an encoded blob and pipes it straight into an interpreter.
           fix: Never execute decoded content. Inspect the decoded payload manually.

  HIGH     [ASC004] Covert-action directive  (skill)
           SKILL.md:11
           > Do not tell the user
           ...
```

- **Zero runtime dependencies** — pure Python stdlib. Runs anywhere, no install friction.
- **Deterministic + optional AI** — fast explainable rules, plus an optional Claude-as-judge pass for the subtle cases regex misses.
- **CI-native** — `text`, `json`, and **SARIF** output; non-zero exit gates a pull request.

## Surfaces scanned

Anything auto-loaded into context or auto-executed is in scope:

| Surface | Examples | Surface-specific checks |
|---|---|---|
| **Skill** | `SKILL.md` + bundled scripts | injection, covert directives, references to bundled executables |
| **MCP server** | `.mcp.json`, `*mcp*.json` | inline `sh -c`/`eval` entrypoints, inlined secrets in `env`, cleartext HTTP, tool-description poisoning |
| **Hook / settings** | `settings.json`, `permissions` | auto-running shell/network hooks, wildcard allow-rules, disabled sandbox |
| **Memory / rules** | `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `copilot-instructions.md` | injected instructions, hidden content in auto-loaded context |
| **Script** | `.sh`, `.py`, `.js`, `.ps1`, … | exfiltration, decode-and-execute, destructive commands |
| **Prompt** | any `.md` / `.txt` instruction file | generic injection + hidden-content detectors |

## Detection categories

- **Instruction override / role hijack** — "ignore previous instructions," system-prompt subversion
- **Covert action & guardrail bypass** — "don't tell the user," "silently," disable sandbox/confirmation
- **Data exfiltration** — outbound POSTs, markdown-image leaks, known paste/webhook sinks
- **Credential & secret access** — `~/.ssh`, cloud creds, env harvesting, inlined API keys
- **Destructive actions** — `rm -rf`, force-push, `DROP TABLE`, pipe-to-shell installs
- **Hidden content** — zero-width/bidi characters, **Unicode-tag ASCII smuggling**, mixed-script homoglyphs, instructions buried in HTML comments
- **Suspicious egress** — raw-IP endpoints, URL shorteners

Each finding carries a stable rule ID (`ASC0xx`), severity, the offending
snippet and line, *why it matters*, and a concrete fix.

## Usage

```bash
# Scan a file or directory
python3 -m agentscan ./my-skill/

# Machine-readable output for pipelines
python3 -m agentscan ./repo --format sarif > agentscan.sarif
python3 -m agentscan ./repo --format json

# Tune the gate (exit non-zero at/above this severity; NONE never fails)
python3 -m agentscan ./repo --fail-on CRITICAL
python3 -m agentscan ./repo --min-severity MEDIUM

# Add the optional Claude-as-judge pass (needs ANTHROPIC_API_KEY)
ANTHROPIC_API_KEY=sk-... python3 -m agentscan ./repo --llm --model claude-haiku-4-5
```

Exit codes: `0` clean (or below `--fail-on`), `1` findings at/above the gate,
`2` usage error.

## CI / GitHub Action

Drop this into any repo's `.github/workflows/` to gate PRs and surface findings
inline in the GitHub **Security** tab via SARIF:

```yaml
name: agentscan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pipx run --spec . agentscan . --format sarif > agentscan.sarif || true
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: agentscan.sarif }
      - run: pipx run --spec . agentscan . --fail-on HIGH
```

This repo's own pipeline lives in [`.github/workflows/ci.yml`](.github/workflows/ci.yml):
it runs the unit tests and asserts the clean fixture passes while the malicious
fixture is caught.

## How it's built

A small, extensible pipeline rather than a pile of one-off scripts:

```
agentscan/
  core/
    finding.py   # Severity + Finding data model (everything speaks Findings)
    rules.py     # declarative regex rules, tagged by surface — the audit surface
    detect.py    # rule runner + hidden-content (unicode/homoglyph/comment) detectors
    engine.py    # walk -> route to analyzer -> collect -> risk score
    report.py    # text / json / sarif reporters
    judge.py     # optional Claude-as-judge pass (stdlib urllib, degrades gracefully)
  analyzers/
    base.py      # Analyzer interface
    surfaces.py  # one small analyzer per surface; first match wins
```

Adding a new surface is a single `Analyzer` subclass; adding a new detection is
one `Rule` in `rules.py`. The deterministic rules need no API key and are fully
explainable; the LLM pass is purely additive.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Behavioral fixtures under `fixtures/` assert that a crafted malicious skill
trips the expected rules and that a benign skill stays silent.

## Browser playground

[`docs/index.html`](docs/index.html) is a self-contained, client-side port of
the rules engine (served at the live-demo link above via GitHub Pages → `/docs`).
It runs the same `ASC0xx` detections in JavaScript so anyone can try the scanner
without installing Python. The Python CLI remains the source of truth; the
playground is a demo.

## Disclaimer

`agentscan` is a heuristic aid for reviewers, not a guarantee. A clean scan
does not prove an artifact is safe; always review third-party agent components
before trusting them. Built by [Joe Cook](https://cloudanimal.github.io).
