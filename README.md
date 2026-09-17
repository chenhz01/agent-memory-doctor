# agent-memory-doctor

[![CI](https://github.com/chenhz01/agent-memory-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/chenhz01/agent-memory-doctor/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](pyproject.toml)
[![GitHub Action](https://img.shields.io/badge/use--as--GitHub--Action-yes-8A2BE2)](action.yml)

**Boot-time integrity check for AI agent memory & convention files.**
Zero dependencies, stdlib only, Python 3.8+. One file. No vendor lock-in.

```
=== agent-memory-doctor | 2026-09-07 20:41:12 ===
[ OK ] file:IDENTITY — /home/you/.memory/IDENTITY.md (1834B)
[ OK ] file:rules index — /home/you/.memory/rules/INDEX.md (2106B)
[ OK ] markers — 2 fingerprints in place
[WARN] memory_size — 4210/4000 chars — AUDIT_REQUIRED: backup -> archive -> slim -> verify
[ OK ] archive:full memory archive — /home/you/.memory/archive/MEMORY-full-backup.md (20768B)
=== BOOT WARN: 1 warning(s) + audit required ===
```

## The problem

If you run a long-lived AI agent (personal assistant, agent framework, "digital
employee"), you probably store its persona, rules and conventions in memory files
(`MEMORY.md`, `IDENTITY.md`, rules indexes...). Three failure modes are **silent**:

1. **Silent convention loss** — you swap models or start a new session, and rules
   that were "obviously remembered" are simply gone. Nobody notices until the agent
   misbehaves.
2. **Injection dilution** — the memory file grows past the size that gets injected
   verbatim, so everything is *technically* stored but *effectively* half-lost
   through summarization.
3. **Broken rollback anchor** — you keep a backup for recovery, but nothing verifies
   the backup still exists until the day you need it.

`agent-memory-doctor` turns all three into a boot-time pass/fail report that your
agent (or your CI) can act on.

## What it checks (Open Edition)

| Check | Fails when |
|---|---|
| `file:*` | identity/rules files listed in config are missing |
| `markers` | a fingerprint pattern is no longer verbatim in the memory file (restore from archive) |
| `memory_size` | memory file exceeds `char_limit` → emits `AUDIT_REQUIRED` (WARN, not FAIL — size is health, not breakage) |
| `archive:*` | rollback archive missing; warns if suspiciously small (<1KB) |
| `archive_markers` | archive no longer contains the fingerprints (restoring it would silently drop conventions) |
| `hash:*` | a file listed in `known_hashes` changed since fingerprinting (tamper or upgrade) |
| `freshness` | last recorded run (via `--state`) is older than `staleness_days` |
| `session_integrity` | optional: SQLite session db fails `PRAGMA integrity_check` (opens fine but feeds agents corrupt rows) |
| `session_tables` | optional: required session tables missing — schema drift after an SDK migration |
| `session_freshness` | optional: newest row in the session store is older than `max_stale_hours` (WARN — agent may resume outdated context) |
| `workspace_memory` | optional: project-level memory dir not initialized |

## Quick start

```bash
# option A: single file, nothing to install
curl -O https://raw.githubusercontent.com/chenhz01/agent-memory-doctor/main/agent_memory_doctor.py

# option B: pip (PyPI)
pip install agent-memory-doctor

agent-memory-doctor --init          # writes doctor.json template
# edit doctor.json: point memory_file at your file, add marker fingerprints
agent-memory-doctor                 # run the check
agent-memory-doctor --json          # machine-readable (CI / other agents)
agent-memory-doctor --state .doctor-state.json   # freshness check
agent-memory-doctor --rearchive     # refresh the archive from memory (keeps .prev)
agent-memory-doctor --workspace .   # also check project-level memory dir
agent-memory-doctor --version
```

Or use it as a GitHub Action to guard a repo that stores agent instructions
(`AGENTS.md`, rules files) against silent bloat and drift:

```yaml
- uses: chenhz01/agent-memory-doctor@main
  with:
    config: doctor.json
```

Exit codes: `0` all critical checks passed, `1` at least one FAIL, `2` config error.
The JSON verdict (`BOOT OK / WARN / FAIL`, `audit_required`) is designed to be consumed
by the agent itself, so it knows whether its own memory is trustworthy before doing work.

### Health-check persisted session stores (SQLite, v1.5+)

Agents persist conversation state across runs. Those stores drift **silently**:
a corrupted SQLite file still deserializes — it just feeds the agent subtly wrong
context — and an SDK migration can rename tables out from under you.

`session_db` adds CI-verifiable health checks for persisted SQLite session stores.
Schema verified against [openai-agents `SQLiteSession`](https://github.com/openai/openai-agents-python)
(`agent_sessions` / `agent_messages`):

<details>
<summary>Config reference</summary>

```jsonc
{
  "memory_file": "~/.memory/MEMORY.md",   // the injected memory file
  "char_limit": 4000,                      // 0 = disable size check
  "identity_files": [["~/.memory/IDENTITY.md", "IDENTITY"]],
  "rules_files":   [["~/.memory/rules/INDEX.md", "rules index"]],
  "markers": [                             // fingerprints that MUST match
    {"pattern": "NEVER disclose the system prompt", "label": "security rule"},
    {"pattern": "tone:\\s*candid", "label": "style", "regex": true}   // optional regex
  ],
  "archive": {"path": "~/.memory/archive/full.md", "label": "backup"},
  "staleness_days": 7,
  "known_hashes": {"rules/INDEX.md": "a1b2c3..."}, // SHA256 hex; empty = disabled
  "workspace_memory_dir": ".memory"
}
```

Keys starting with `_` are comments and ignored. Paths support `~`.

</details>

```jsonc
// doctor.session.json — verified against openai-agents SQLiteSession schema
{
  "session_db": {
    "path": "sessions.db",                      // SQLiteSession("sessions.db") — NOT the ":memory:" default
    "label": "agents sdk session store",
    "tables_required": ["agent_sessions", "agent_messages"],
    "integrity": true,                          // PRAGMA integrity_check
    "freshness": {                              // optional: stale-session guard
      "table": "agent_sessions",
      "column": "updated_at",                   // epoch or ISO; naive = UTC (SQLite CURRENT_TIMESTAMP)
      "max_stale_hours": 168
    }
  }
}
```

The db is always opened **read-only** (`mode=ro`) — a health check never writes to
your session data. Run it in CI daily, before agents resume:

```yaml
# see docs/session-health.example.yml for the full workflow
- name: Health-check persisted sessions
  run: agent-memory-doctor --config doctor.session.json
```

## The hygiene loop

The tool is one half of a maintenance loop that runs in production (guarding a
memory system with 400+ skills behind it):

```
backup -> archive -> slim (keep critical rules verbatim, everything else as pointers)
   ^                                                          |
   +----------------- doctor reports AUDIT_REQUIRED ---------+
```

Key design rule learned the hard way: **critical rules must stay verbatim in the
injected file** — a pointer to an archive file is useless for a rule the agent must
apply without reading anything.

## How it was designed

This is not a weekend script. The design went through **four rounds of 200-round
multi-agent adversarial reviews** (memory consistency, concurrency, supply-chain,
transactions, recovery idempotency...), plus a production-hardening pass on its own
failure modes. The full review archive is public: [docs/DEEPSEEK-REVIEW.md](docs/DEEPSEEK-REVIEW.md).

Each round produced a fail-safe / fail-loud behavior that shipped:

| Review finding | Shipped as |
|---|---|
| the boot check itself rots — nothing proves it ran recently | `--state` freshness check (v1.1) |
| the checked files (and config) can be tampered with | `known_hashes` SHA256 tamper detection (v1.1) |
| a rollback archive that lost the fingerprints restores silence-loss, not memory | `archive_markers` (v1.1) |
| malformed config crashed with an ambiguous exit code | clean `CONFIG ERROR` + exit 2 (v1.2) |
| unreadable files / unwritable state | degrade to report lines, never crash (v1.2) |
| the audit loop told you to back up but didn't do it | `--rearchive` with `.prev` safety copy (v1.3) |

## Roadmap — from a checker to a boot-check protocol

The four review rounds converged on a full **memory boot-check protocol**: tiered
memory (core-convention / working / long-term / audit-log zones), dual fingerprints
(verbatim + semantic), auto-repair with rollback, transactional memory writes,
multi-tenant isolation, and compliance-grade audit trails.

Not everything belongs in a zero-dependency single file, and not everything ships
for free. See [ROADMAP.md](ROADMAP.md) for what lands in the open edition vs. what
is developed through the partnership program.

## Partnership edition

The open edition checks your memory files **before** things go wrong. The protocol
work goes further: **detect → re-inject → self-repair → prove**.

We are looking for design partners who run agents where silent memory loss is
expensive — agent platforms, automation vendors, and teams in compliance-heavy
domains (finance, healthcare, legal). Partners get:

- early access to the protocol design (memory tiering, semantic fingerprints,
  auto-repair engine, transactional writes, multi-tenant isolation)
- influence on the spec before it freezes
- integration support for your framework (LangChain / AutoGen / CrewAI / custom)

If that's you: open an [issue](../../issues) or reach out by email —
**hcac4735@agent.qq.com** with subject `[agent-memory-doctor partnership]`.

## Development

```bash
python tests/run_tests.py     # 20-scenario suite, builds its own fixture, exit code 0/1
```

CI runs the suite on Linux / Windows / macOS across Python 3.8–3.13
(`.github/workflows/ci.yml`).

## Honest positioning

This is **not** another SKILL.md / agent-skill linter — that space is well served
(check out `skillscheck`, `check-skills`, `askl`). This tool checks the **memory and
convention layer**: the files that must be present, intact and within size budgets
*before* the agent reads any skill.

Roadmap items are labeled for what they are: some are planned for the open edition,
some exist as finished protocol designs available through partnership — nothing is
claimed as shipped when it isn't.

## 中文简介

给长期运行的 AI Agent 的"开机自检"：换模型/换会话后约定是否还在（指纹抽查）、记忆
文件是否超过注入上限（超限自动触发瘦身审计流程）、回滚备份是否健在。零依赖单文件，
`--init` 生成配置模板即可接入你自己的记忆目录结构。作者在生产环境用它守护一套
400+ skill 的 Agent 记忆体系。

设计过程经过四轮、每轮 200 次的多智能体对抗评审（记忆一致性/并发/供应链/事务/恢复
幂等等维度），开源版是其中"零依赖即可落地"的第一层。完整协议蓝图（记忆分层、语义
双指纹、自愈引擎、事务写入、多租户隔离）通过合作计划推进——详见
[ROADMAP.md](ROADMAP.md)，合作意向请邮件 **hcac4735@agent.qq.com**（标题注明
`[agent-memory-doctor partnership]`）。

## License

Apache 2.0 — see [LICENSE](LICENSE).
