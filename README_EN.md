# backdoor-check

> Defending your right to know what your AI coding tools do — local-only, zero egress by default, open-source.

English ｜ **[中文](README.md)**

Ships with complete Claude Code support first, and uses extensible adapters for Cursor / GitHub Copilot / Windsurf / Cline / Aider / Continue and other AI coding tools. It inspects mechanisms **worth your knowing**: undisclosed network egress, device fingerprinting, credential redirection, suspicious Hooks / MCP / plugin behavior, and prompt steganography.

**It does not render a "yes/no backdoor" verdict for you. It surfaces the mechanisms, and lays them out for you to see.**

---

## What it checks

Nine dimensions — each a class of mechanism worth knowing about:

| Code | Dimension | What it inspects |
|------|-----------|------------------|
| A | Version & supply chain | Version within a reported range / package origin / integrity baseline / official registry cross-check |
| B | Network egress | Process-connection snapshots / telemetry endpoint hits / traffic-switch effectiveness / hosts tampering / outbound allowlist / private-network egress / TLS validation |
| C | Device fingerprint | Geolocation APIs / machine-ID reads / identity env vars / hardcoded collection functions in the binary |
| D | Hooks | Full scan / clone-propagated scripts / undeclared hooks / dangerous commands / script auditing |
| E | MCP | Server inventory / launch-command credibility / permission overrides / stdio hijack surface |
| F | API & credentials | base_url redirection / plaintext storage / file permissions / credentials on the command line |
| G | Permissions & dangerous config | Dangerous toggles / high-risk allow-rules / alias injection / over-broad wildcards |
| H | Plugin supply chain | Marketplace origin / code audit / blocklist / integrity |
| I | Prompt steganography | Steganographic signatures + decoding / trigger-condition assessment (whether you belong to a targeted group) |

> Dimension I uses **deterministic signature detection** (not heuristics): byte-level, reproducible matching against the disclosed techniques (apostrophe Unicode variants, date `-`→`/` transformation, XOR+base64 domain lists).

---

## How it respects you

A security-detection tool should not, itself, become a new privacy risk. backdoor-check enforces this in engineering:

- **Local-only, no egress (double guarantee):** static self-audit (no network symbols in `scripts/`) + a runtime socket guard (blocks outbound on startup; any connection throws). The sole exception is `--verify-registry`, which contacts the official registry via an isolated subprocess and only GETs the manifest — **carrying no local data**.
- **Redacted reports:** every credential passes through `redact()`, replaced with `<redacted:len=N:hash=sha256[:8]>` so you can compare without exposing the original.
- **Fully auditable:** `--audit` dry-runs and prints every system command that would run; all scripts are pure Python, readable, unobfuscated.
- **Zero dependencies:** no third-party libraries pulled in (the rule library is JSON, not YAML, to avoid the PyYAML dependency) — no new supply-chain risk added to your environment.

These are not selling points. They are the precondition for asking you to trust it.

---

## Quick start

```bash
# 1. First verify the tool itself (static no-egress + runtime guard + redaction)
python3 scripts/check.py --self-check

# 2. Full checkup (human-readable markdown report)
python3 scripts/check.py --mode interactive

# 3. CI mode (JSON + exit code; exits 2 on crit)
python3 scripts/check.py --mode ci --format json --dims A,B,F
echo "exit: $?"  # 0=pass / 1=warn / 2=crit

# 4. Single dimension
python3 scripts/check.py --dim network --format text

# 5. Deep forensics (sudo dtrace/strace guidance; confirms actual exfiltration)
python3 scripts/check.py --mode deep

# 6. Controlled egress: cross-check package integrity against the official registry
python3 scripts/check.py --verify-registry

# 7. Audit dry-run (prints commands without executing them)
python3 scripts/check.py --audit
```

If Windows PowerShell renders Chinese text or symbols incorrectly, run:

```powershell
$env:PYTHONUTF8 = "1"
py scripts\check.py --self-check
```

**Report severity:** 🚨 `crit` (backdoor signatures / credential leaks / arbitrary execution — act now) / ⚠️ `warn` (risk surface & hardening advice) / ✅ `pass` / ℹ️ `info`.

---

## As a Claude Code skill / standalone CLI

**As a skill:** place this directory at `~/.claude/skills/backdoor-check/`, then trigger it in natural language — "backdoor check", "security checkup", "is Claude Code safe", "NVDB backdoor", etc. (full trigger list in `SKILL.md`).

**As a standalone CLI:** `check.py` has no Claude dependency and runs anywhere:

```bash
python3 /path/to/backdoor-check/scripts/check.py --mode quick
```

---

## Universality (beyond Claude Code)

The `claude-code` adapter ships first and is complete. Other tools are supported by contributing adapters:

- Adapter interface: `discover()` / `config_paths()` / `known_endpoints()` / `integrity_targets()` / `process_names()`
- New-adapter process in `references/adapters-guide.md`
- **Tool-agnostic fallback:** without an adapter, the engine heuristically collects connections by process behavior and diffs them against a generic allowlist — surfacing "unknown AI-tool process egress" alerts.

Roadmap: Phase 1 `claude-code`; Phase 2+ `cursor` / `windsurf` / `cline` / `copilot` / `aider` / `continue` (community contributions welcome).

---

## CI integration

```yaml
# GitHub Actions example
- name: backdoor-check
  run: |
    python3 skills/backdoor-check/scripts/check.py --mode ci --format json --dims A,B,F
```

Exit code `0` all pass / `1` has warn / `2` has crit. JSON schema in `references/ci-integration.md`.

---

## Honest limits

No one can promise "absolute security," and this tool is no exception. Before trusting its conclusions, please understand its limits:

1. Binaries are compiled artifacts (e.g. `claude.exe`, hundreds of MB); `strings` / `otool` / `nm` only hit the unobfuscated portions → **this is heuristic evidence; "not found" ≠ "does not exist."**
2. `lsof` is an instantaneous snapshot and misses the full picture of periodic beacons (a watch mode is planned).
3. Behavioral forensics (whether data is **actually** exfiltrated) require `sudo`; `deep` mode provides guidance but does not run them by default.
4. Rules are not auto-fetched over the network (no egress by design) — they update manually or ship with releases.
5. Inspecting binaries of commercial closed-source tools may touch EULA; this tool is positioned as "auditing your personal environment," not an enterprise-compliance substitute.
6. Rootkit-level concealment (a backdoor detecting this tool and hiding) is beyond its reach.

If your threat model involves any of the above, combine layered defenses — do not rely on a single tool.

---

## Contributing

To contribute is, itself, to take part in technological parity — letting more people audit their own tools.

- **New adapters** (more AI tools): see `references/adapters-guide.md`
- **New detection rules** (JSON rule library): `scripts/rules/`, format in each file's notes
- **New dimensions**: follow the `references/check-standards.md` template
- **False-positive / false-negative reports**: attach a redacted report snippet and tool version

---

## Directory layout

```
backdoor-check/
├── SKILL.md                # Skill entry (Claude Code triggers)
├── README.md               # Chinese (this project's primary README)
├── README_EN.md            # English
├── LICENSE                 # MIT
├── references/             # Detailed docs (loaded on demand)
│   ├── check-standards.md  # A–I dimension standards + thresholds
│   ├── deep-water.md       # Network commands / binary analysis / behavioral forensics
│   ├── adapters-guide.md   # Adapter contract + new-adapter guide
│   ├── rules-guide.md      # Rule-library authoring guide
│   ├── ci-integration.md   # JSON schema + CI snippets
│   └── self-security.md    # Self-security engineering details
└── scripts/
    ├── check.py            # CLI entry (includes outbound socket guard)
    ├── selfcheck.py        # Static self-audit
    ├── verify_registry.py  # The only controlled-egress module
    ├── capture_prompt.py   # Prompt-steganography runtime diagnostics (advanced; temporarily rewrites base_url)
    ├── engine/             # Tool-agnostic detection primitives
    ├── adapters/           # Tool adaptation layer
    └── rules/              # JSON rule library (community-extensible)
```

---

## Acknowledgments & Statement

### It began with a marker

In June 2026, security researcher **Thereallo** published a reverse-engineering analysis of Claude Code. It described a path related to a custom `ANTHROPIC_BASE_URL` in which the client encoded environment signals into the system prompt: the date separator and the apostrophe in `Today's` remain almost indistinguishable in ordinary rendering, while still being machine-readable. The domain and keyword lists were further processed with XOR (key 91) and base64. The technical details are in [the original analysis](https://thereallo.dev/blog/claude-code-prompt-steganography).

This is not evidence that every user was marked, nor a blanket verdict on any piece of software. The report shows that the path returns early when `ANTHROPIC_BASE_URL` is unset or points to the official API. That is why backdoor-check treats it as a **reproducible historical signature**: it applies to particular versions, configurations, and evidence—not panic in place of judgment.

We thank every researcher who turns a complicated mechanism into something others can review. This project inherits not only the question they raised, but their method: take things apart, explain them, and leave them open to challenge.

### A legitimate aim does not replace transparency

Model providers have reason to defend against account resale, abuse, and industrial-scale distillation. Anthropic has publicly described distillation campaigns involving fraudulent accounts and proxy services. [Its public account](https://www.anthropic.com/news/detecting-and-preventing-distillation-attacks?selectAccount=true) makes clear that this is a real conflict requiring real defenses.

But a legitimate goal does not remove the duty to explain the means. When a developer tool can already read projects, execute commands, and enter a workflow, users should not need reverse engineering to learn how their environment is being classified. Anti-abuse measures can be explicit policies, visible telemetry fields, and auditable rules; consequential signals should not be hidden in details ordinary people cannot reasonably see.

### Knowing is a public relationship

Technology is not only a collection of features. It also determines who sets the rules, who must accept the defaults, and who gets to explain them. As computational tools move deeper into work, creation, and public life, that asymmetry should not be treated as natural.

Our proposition is modest: every user has the right to know whether their environment is being collected, classified, or transmitted. That right should not depend on location, language, the size of an organization, or the company whose tool is in use.

This is the limited work backdoor-check takes on: run locally by default, redact reports first, keep dependencies minimal, and lower the cost of examining process behavior, network connections, configuration, supply-chain clues, device fingerprints, and prompt steganography. It does not appoint enemies or demand that you accept its verdict. It tries to make otherwise invisible mechanisms visible.

We welcome reproductions, corrections, new rules, and new adapters. We also welcome tool maintainers to challenge this project with clearer disclosure, smaller data-collection surfaces, and more auditable implementations. A tool worthy of trust should not fear being seen.

---

## License

MIT — see [LICENSE](LICENSE).

If this tool leaves you a little clearer about what you use every day, it has done what it was made for.
