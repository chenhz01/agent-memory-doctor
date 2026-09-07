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
python agent_memory_doctor.py --workspace .   # also check project-level memory dir
```

Exit codes: `0` all critical checks passed, `1` at least one FAIL, `2` config missing.

## What it checks

| Check | Fails when |
|---|---|
| `file:*` | identity/rules files listed in config are missing |
| `markers` | a fingerprint pattern is no longer verbatim in the memory file (restore from archive) |
| `memory_size` | memory file exceeds `char_limit` → emits `AUDIT_REQUIRED` (WARN, not FAIL — size is health, not breakage) |
| `archive:*` | rollback archive missing; warns if suspiciously small (<1KB) |
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
  "archive": {"path": "~/.memory/archive/full.md", "label": "backup"}
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
