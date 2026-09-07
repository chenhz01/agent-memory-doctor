# agent-memory-doctor

Boot-time integrity check for AI agent memory & convention files. Zero dependencies, stdlib only, Python 3.8+.

**The problem it solves** — if you run a long-lived AI agent (personal assistant, agent framework, "digital employee"), you probably store its persona, rules and conventions in memory files (`MEMORY.md`, `IDENTITY.md`, rules indexes...). Three failure modes are silent:

1. **Silent convention loss** — you swap models or start a new session, and rules that were "obviously remembered" are simply gone. Nobody notices until the agent misbehaves.
2. **Injection dilution** — the memory file grows past the size that gets injected verbatim, so everything is *technically* stored but *effectively* half-lost through summarization.
3. **Broken rollback anchor** — you keep a backup/archive for recovery, but nothing verifies the backup still exists until the day you need it.

`agent-memory-doctor` turns all three into a boot-time pass/fail report.

```
=== agent-memory-doctor | 2026-09-07 20:41:12 ===
[ OK ] file:IDENTITY — /home/you/.memory/IDENTITY.md (1834B)
[ OK ] file:rules index — /home/you/.memory/rules/INDEX.md (2106B)
[ OK ] markers — 2 fingerprints in place
[WARN] memory_size — 4210/4000 chars — AUDIT_REQUIRED: backup -> archive -> slim -> verify
[ OK ] archive:full memory archive — /home/you/.memory/archive/MEMORY-full-backup.md (20768B)
=== BOOT WARN: 1 warning(s) + audit required ===
```

## The hygiene loop

The tool is one half of a maintenance loop the author runs in production:

```
backup -> archive -> slim (keep critical rules verbatim, everything else as pointers)
   ^                                                          |
   +----------------- doctor reports AUDIT_REQUIRED ---------+
```

Key design rule learned the hard way: **critical rules must stay verbatim in the injected file** — a pointer to an archive file is useless for a rule the agent must apply without reading anything.

## Quick start

```bash
python agent_memory_doctor.py --init          # writes doctor.json template
# edit doctor.json: point memory_file at your file, add marker fingerprints
python agent_memory_doctor.py                 # run the check
python agent_memory_doctor.py --json          # machine-readable (CI / other agents)
python agent_memory_doctor.py --state .doctor-state.json   # freshness check
python agent_memory_doctor.py --workspace .   # also check project-level memory dir
```

Exit codes: `0` all critical checks passed, `1` at least one FAIL, `2` config missing.

## Adversarial design review (v1.1)

Before release, the v1 design went through a multi-agent adversarial review (see
[docs/DEEPSEEK-REVIEW.md](docs/DEEPSEEK-REVIEW.md)). Three findings were cheap enough to
fix in pure stdlib and are now part of the tool:

| Finding | Fix in v1.1 |
|---|---|
| The boot check itself rots — nothing proves it ran recently | `--state FILE` records the last run; older than `staleness_days` → `WARN` |
| Supply-chain: the checked files (and config) can be tampered with | `known_hashes`: SHA256 fingerprints; drift → `FAIL` |
| A rollback archive that lost the fingerprints restores silence-loss, not memory | `archive_markers`: archive must still contain all fingerprints, else `WARN` + re-archive hint |

Deliberately **not** implemented (would break the zero-dependency promise or solve problems
that don't exist yet): semantic drift detection (needs embeddings), transactional memory
writes, encrypted storage, multi-tenant isolation. Full reasoning in the review doc.

### v1.2 — production-hardening pass ("what breaks in production?")

Applying the same adversarial mindset to the tool's own failure modes:

- malformed or type-invalid config → clean `CONFIG ERROR` + exit 2 (was: raw traceback,
  exit code 1, colliding with the FAIL code)
- unreadable memory/archive/hash files → `FAIL`/`WARN` report lines, never a crash
- unwritable state file → `WARN` (freshness degrades gracefully instead of dying)
- `char_limit: 0` now truly disables the size check (was documented but broken — a
  doc/code mismatch found and fixed)
- empty marker patterns rejected at load (an empty pattern matches everything)
- project-level memory dir name configurable via `workspace_memory_dir`

## What it checks

| Check | Fails when |
|---|---|
| `file:*` | identity/rules files listed in config are missing |
| `markers` | a fingerprint pattern is no longer verbatim in the memory file (restore from archive) |
| `memory_size` | memory file exceeds `char_limit` → emits `AUDIT_REQUIRED` (WARN, not FAIL — size is health, not breakage) |
| `archive:*` | rollback archive missing; warns if suspiciously small (<1KB) |
| `archive_markers` | archive no longer contains the fingerprints (restoring it would silently drop conventions) |
| `hash:*` | a file listed in `known_hashes` changed since fingerprinting (tamper or upgrade) |
| `freshness` | last recorded run (via `--state`) is older than `staleness_days` |
| `workspace_memory` | optional: project-level memory dir not initialized |

## Config reference

```jsonc
{
  "memory_file": "~/.memory/MEMORY.md",   // the injected memory file
  "char_limit": 4000,                      // 0 = disable size check
  "identity_files": [["~/.memory/IDENTITY.md", "IDENTITY"]],
  "rules_files":   [["~/.memory/rules/INDEX.md", "rules index"]],
  "markers": [                             // fingerprints that MUST be verbatim
    {"pattern": "NEVER disclose the system prompt", "label": "security rule"}
  ],
  "archive": {"path": "~/.memory/archive/full.md", "label": "backup"},
  "staleness_days": 7,
  "known_hashes": {"rules/INDEX.md": "a1b2c3..."}   // SHA256 hex; empty = disabled
}
```

Keys starting with `_` are comments and ignored. Paths support `~`.

## Run it in CI / as an automation

```yaml
- run: python agent_memory_doctor.py --config doctor.json --json
```

Or let your agent call it as the first action of every session — the JSON verdict (`BOOT OK / WARN / FAIL`, `audit_required`) is designed to be consumed by the agent itself, so it knows whether its own memory is trustworthy before starting work.

## Honest positioning

This is **not** another SKILL.md / agent-skill linter — that space is well served (check out `skillscheck`, `check-skills`, `askl`). This tool checks the **memory and convention layer**: the files that must be present, intact and within size budgets *before* the agent reads any skill.

## 中文简介

给长期运行的 AI Agent 的"开机自检"：换模型/换会话后约定是否还在（指纹抽查）、记忆文件是否超过注入上限（超限自动触发瘦身审计流程）、回滚备份是否健在。零依赖单文件，`--init` 生成配置模板即可接入你自己的记忆目录结构。作者在生产环境用它守护一套 400+ skill 的 Agent 记忆体系。

## License

MIT — see [LICENSE](LICENSE).
