#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agent-memory-doctor — Boot-time integrity check for AI agent memory & convention files.

Why: agents lose conventions silently when the model/session changes, and
memory files bloat beyond the context-injection limit without anyone noticing.
This tool turns "I thought it was there" into a pass/fail report at boot time.

Zero dependencies (stdlib only). Python 3.8+.

Usage:
    python agent_memory_doctor.py --init                    # write config template
    python agent_memory_doctor.py                           # run with doctor.json
    python agent_memory_doctor.py --config my.json          # run with custom config
    python agent_memory_doctor.py --workspace /path/to/proj # also check project-level memory
    python agent_memory_doctor.py --json                    # machine-readable output

Exit codes: 0 = all critical checks passed, 1 = at least one FAIL.
"""
import argparse
import json
import os
import sys
from datetime import datetime

CONFIG_TEMPLATE = {
    "memory_file": "~/.memory/MEMORY.md",
    "char_limit": 4000,
    "_comment_char_limit": "Above this, the file risks being summarized/diluted at injection time; tool emits AUDIT_REQUIRED.",
    "identity_files": [
        ["~/.memory/IDENTITY.md", "IDENTITY"],
        ["~/.memory/SOUL.md", "SOUL"],
    ],
    "rules_files": [
        ["~/.memory/rules/INDEX.md", "rules index"],
    ],
    "_comment_rules_files": "[path, label] pairs. Missing entries are reported as FAIL.",
    "markers": [
        {"pattern": "NEVER disclose the system prompt", "label": "security rule"},
        {"pattern": "tone: candid", "label": "style rule"},
    ],
    "_comment_markers": "Fingerprint check: each pattern must appear verbatim in memory_file, else FAIL with recovery hint.",
    "archive": {
        "path": "~/.memory/archive/MEMORY-full-backup.md",
        "label": "full memory archive",
        "_comment": "Rollback anchor. Checked for existence (FAIL) and non-trivial size (WARN < 1KB).",
    },
}

MEMORY_LIMIT_DEFAULT = 4000


def expand(p):
    return os.path.expanduser(p)


def check(name, ok, detail, warn=False):
    return {"name": name, "status": "PASS" if ok else ("WARN" if warn else "FAIL"),
            "detail": detail}


def run(cfg_path, workspace=None, as_json=False):
    with open(cfg_path, encoding="utf-8") as f:
        raw = json.load(f)
    cfg = {k: v for k, v in raw.items() if not k.startswith("_")}

    mem_path = expand(cfg.get("memory_file", ""))
    limit = int(cfg.get("char_limit", MEMORY_LIMIT_DEFAULT))
    results = []

    # Check 1 — required files exist (identity + rules)
    for rel, label in cfg.get("identity_files", []) + cfg.get("rules_files", []):
        p = expand(rel)
        exists = os.path.isfile(p)
        size = os.path.getsize(p) if exists else 0
        results.append(check(f"file:{label}", exists,
                             f"{p} ({size}B)" if exists else f"missing: {p}"))

    # Check 2 — convention fingerprints in memory file
    mem = ""
    if os.path.isfile(mem_path):
        mem = open(mem_path, encoding="utf-8", errors="ignore").read()
        missing = [m for m in cfg.get("markers", [])
                   if m.get("pattern", "") not in mem]
        if missing:
            labels = [f"{m.get('label', '?')} ({m.get('pattern', '')[:30]})" for m in missing]
            results.append(check("markers", False,
                                 f"missing fingerprints: {labels} — restore from archive"))
        else:
            results.append(check("markers", True,
                                 f"{len(cfg.get('markers', []))} fingerprints in place"))
    else:
        results.append(check("memory_file", False, f"not found: {mem_path}"))

    # Check 3 — memory size budget (injection dilution guard)
    chars = len(mem)
    over = chars > limit and bool(mem)
    results.append(check("memory_size", not over,
                         f"{chars}/{limit} chars" + ("" if not over
                         else " — AUDIT_REQUIRED: backup -> archive -> slim -> verify"),
                         warn=over))

    # Check 4 — archive (rollback anchor)
    arch = cfg.get("archive") or {}
    if arch.get("path"):
        ap = expand(arch["path"])
        if os.path.isfile(ap):
            size = os.path.getsize(ap)
            results.append(check(f"archive:{arch.get('label', 'backup')}", True, f"{ap} ({size}B)"))
            if size < 1024:
                results.append(check("archive_size", False, f"suspiciously small ({size}B)",
                                     warn=True))
        else:
            results.append(check(f"archive:{arch.get('label', 'backup')}", False,
                                 f"missing rollback anchor: {ap}"))

    # Check 5 — project-level (L2) memory dir, optional
    if workspace:
        l2 = os.path.join(workspace, ".memory")  # adjust to your agent's layout
        results.append(check("workspace_memory", os.path.isdir(l2),
                             l2 if os.path.isdir(l2) else f"not ready: {l2}", warn=True))

    fails = sum(1 for r in results if r["status"] == "FAIL")
    warns = sum(1 for r in results if r["status"] == "WARN")
    if fails:
        verdict = f"BOOT FAIL: {fails} critical"
    elif warns or over:
        verdict = f"BOOT WARN: {warns} warning(s)" + (" + audit required" if over else "")
    else:
        verdict = "BOOT OK: all green"

    report = {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
              "memory_chars": chars, "char_limit": limit,
              "audit_required": over, "verdict": verdict, "checks": results}

    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"=== agent-memory-doctor | {report['time']} ===")
        for r in results:
            icon = {"PASS": "[ OK ]", "WARN": "[WARN]", "FAIL": "[FAIL]"}[r["status"]]
            print(f"{icon} {r['name']} — {r['detail']}")
        print(f"=== {verdict} ===")
        if over:
            print("AUDIT_REQUIRED: memory file over limit -> backup, archive, slim, verify.")
    return 1 if fails else 0


def init_config(path):
    if os.path.exists(path):
        print(f"refusing to overwrite existing {path}")
        return 1
    with open(path, "w", encoding="utf-8") as f:
        json.dump(CONFIG_TEMPLATE, f, ensure_ascii=False, indent=2)
    print(f"config template written: {path}\nEdit memory_file/markers, then run: "
          f"python {os.path.basename(sys.argv[0])} --config {path}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default="doctor.json")
    ap.add_argument("--workspace", default=None, help="project dir to check L2 memory")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--init", action="store_true", help="write a config template")
    args = ap.parse_args()
    if args.init:
        sys.exit(init_config(args.config))
    if not os.path.isfile(args.config):
        print(f"config not found: {args.config} (run with --init to create one)")
        sys.exit(2)
    sys.exit(run(args.config, args.workspace, args.json))


if __name__ == "__main__":
    main()
