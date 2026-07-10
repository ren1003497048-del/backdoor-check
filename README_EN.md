# backdoor-check

> Defending your right to know what your AI coding tools do — local-only, zero outbound, open-source.

English ｜ **[中文](README.md)**

Detects whether AI coding tools and agents — Claude Code / Cursor / GitHub Copilot / Windsurf / Cline / Aider / Continue — contain mechanisms **worth your knowing**: undisclosed network egress, device fingerprinting, credential redirection, suspicious Hooks / MCP / plugin behavior, prompt steganography.

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

In late June 2026, a developer going by **Thereallo** uncovered the backdoor mechanism in Claude Code; before him, Reddit user **LegitMichel777** had already completed the decompilation. They found something unusual: this coding assistant, trusted by countless developers worldwide, would silently rewrite the system prompt it sent back to its own servers — swapping the hyphens in dates for slashes, and replacing the apostrophe in "Today's date is" with one of three Unicode characters indistinguishable to the human eye yet instantly legible to a machine. The trigger was a timezone (Asia/Shanghai, Asia/Urumqi), or a proxy address containing Chinese domains and AI labs; the domain list itself was hidden behind XOR (key 91) and base64. There was no disclosure at any point — no popup, no consent prompt, no mention in any release notes.

Thereallo wrote something we agree with entirely: **"This is not a malicious feature, but it is a weird choice for a developer tool that asks for trust."** Our thanks to them. Their findings and methods are both the reason this project exists and the method it uses: taking apart and exposing the inner mechanisms of these tools, to protect the rights of every ordinary user standing across from a hundred-billion-dollar giant.

---

On June 30, 2026, Claude Code engineer **Thariq Shihipar** responded on X: this was "an experiment we launched in March that was meant to prevent account abuse from unauthorized resellers and protect against distillation"; the team already had stronger mitigations and had "actually been meaning to take this down for a while."

We understand the concern about distillation. Training a frontier model is enormously expensive, and having its capabilities copied at scale is a loss no company wishes to bear; Anthropic has pointed to large numbers of fraudulent accounts running systematic distillation against Claude. The conflict of interest is real.

**But to understand is not to condone.**

The criterion was set as timezone and geography — any device whose system clock pointed to China, or whose traffic passed through a Chinese network, was flagged by default as worth marking. Tens of millions of ordinary Chinese users like me were presumed guilty, without their knowledge — as if each one had come to feast on its fruits.

Anthropic has always stood on safety: it places "frontier AI safety" at the center of its mission and holds "helpful, harmless, honest" as the creed its models keep. Yet this time, the "safety" it spoke of was its own — the safety of its models not being copied, its commercial interests not being eroded; the user's safety, the safety of knowing how one is being marked, categorized, and where one's data is sent, did not seem to figure in it at all. This suggests, at the very least, that the safety it emphasizes is a narrow one. It also suggests that when an AI giant is at once the rule-maker, the enforcer, and the interpreter, a certain inadvertence becomes, almost inevitably, structural arrogance — and its declarations on safety and transparency become, once again, hard to credit.

---

I hold to a simple proposition: every user has the right to know how their information is collected, how it flows, and how it is treated. This should not depend on where you come from, nor on which company's tool you use.

This is what backdoor-check sets out to do: a local tool for developers and individual users — runs purely locally, makes no outbound requests, redacts its reports, and depends on no third-party libraries; from the mechanism level — process behavior, network egress, static binary analysis, device fingerprinting, prompt steganography — it detects whether the mechanisms worth your knowing are present in your tools. It already covers Claude Code, and is designed to extend to Cursor, Copilot, Windsurf, Cline, Aider, Continue, and any AI coding tool you can name.

---

Finally, we call on more people — researchers like Thereallo, and every ordinary user alike — to protect their own data rights while respecting the privacy of others, throughout their use of AI. These two things should never have been in conflict.

AI was supposed to make the world a little better. Even if, at this moment, it does not appear so. We face, all at once, the torrent of misinformation it brings, the shock to employment, and a string of ethical dilemmas yet unresolved. And the deeper reckoning may be this: AI did not invent prejudice out of thin air — the misogyny, the techno-supremacy, the narcissistic self-centeredness so commonly visible on it are merely the reflection of a shape our society already holds.

---

## License

MIT — see [LICENSE](LICENSE).

If this tool leaves you a little clearer about what you use every day, it has done what it was made for.
