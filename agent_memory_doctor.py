#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agent-memory-doctor — Boot-time integrity check for AI agent memory & convention files.

Why: agents lose conventions silently when the model/session changes, and
memory files bloat beyond the context-injection limit without anyone noticing.
This tool turns "I thought it was there" into a pass/fail report at boot time.

Zero dependencies (stdlib only). Python 3.8+.

v1.5 changes (SQLite session-store health):
  - optional "session_db" config: health-checks persisted SQLite session stores
    (openai-agents SQLiteSession compatible): PRAGMA integrity_check, required
    tables (schema drift), freshness decay on a timestamp column
  - always opens the database read-only (mode=ro) — a health check never writes

v1.3 changes (gap-fill round):
  - --rearchive: perform the "backup -> archive" step the AUDIT_REQUIRED loop
    asks for (previous archive is kept as <archive>.prev)
  - markers support "regex": true (semantic-ish matching without embeddings)
  - --version
  - encoding sanity: mojibake (U+FFFD) in memory/archive -> WARN
  - repo ships an automated test suite (tests/run_tests.py) + GitHub Actions CI

v1.2 changes (AI-assisted code review pass — "what breaks in production"):
  - malformed/invalid config now exits cleanly with code 2 (was: raw traceback,
    which collided with the FAIL exit code)
  - unreadable memory/archive files report FAIL/WARN instead of crashing
  - unwritable state file degrades to WARN (freshness check is advisory)
  - char_limit: 0 truly disables the size check (was documented but broken)
  - empty marker patterns are rejected at config load instead of silently passing
  - project-level memory dir is configurable (workspace_memory_dir)

v1.1 changes (from adversarial design review, see docs/DEEPSEEK-REVIEW.md):
  - --state records last run; stale runs emit WARN (boot checks rot too)
  - known_hashes (SHA256) tamper detection for checked files
  - archive must contain all convention fingerprints (rollback viability)

Usage:
    python agent_memory_doctor.py --init                    # write config template
    python agent_memory_doctor.py                           # run with doctor.json
    python agent_memory_doctor.py --config my.json          # run with custom config
    python agent_memory_doctor.py --state .doctor-state.json
    python agent_memory_doctor.py --rearchive               # backup memory -> archive
    python agent_memory_doctor.py --workspace /path/to/proj # also check project-level memory
    python agent_memory_doctor.py --json                    # machine-readable output

Exit codes: 0 = no critical FAIL, 1 = at least one FAIL, 2 = config error.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import time
from datetime import datetime, timezone

VERSION = "1.5.0"

CONFIG_TEMPLATE = {
    "memory_file": "~/.memory/MEMORY.md",
    "char_limit": 4000,
    "_comment_char_limit": "Above this, the file risks being summarized/diluted at injection time; tool emits AUDIT_REQUIRED. Set 0 to disable the size check.",
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
    "_comment_markers": "Fingerprint check: each pattern must match memory_file, else FAIL with recovery hint. Optional \"regex\": true treats pattern as a regular expression. Empty patterns are rejected.",
    "archive": {
        "path": "~/.memory/archive/MEMORY-full-backup.md",
        "label": "full memory archive",
        "_comment": "Rollback anchor. Checked for existence, non-trivial size, and that it still matches all markers (otherwise restoring it would silently drop your conventions). --rearchive refreshes it from memory_file, keeping the previous one as <path>.prev.",
    },
    "staleness_days": 7,
    "_comment_staleness": "If --state is used and the last run is older than this, emit WARN: your boot check itself has a freshness requirement.",
    "known_hashes": {},
    "_comment_known_hashes": "Supply-chain tamper detection: map of file path -> sha256 hex. Mismatch = FAIL. Generate with: python -c \"import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())\" <file>",
    "workspace_memory_dir": ".memory",
    "_comment_workspace": "Directory name checked under --workspace (project-level memory).",
    "_comment_session_db": "Optional (v1.5) SQLite session-store health check, e.g. openai-agents SQLiteSession('sessions.db'): {\"path\": \"sessions.db\", \"label\": \"agent session store\", \"tables_required\": [\"agent_sessions\", \"agent_messages\"], \"integrity\": true, \"freshness\": {\"table\": \"agent_sessions\", \"column\": \"updated_at\", \"max_stale_hours\": 168}}",
}

MOJIBAKE = "\ufffd"


class ConfigError(Exception):
    """Invalid or unusable configuration — maps to exit code 2."""


def expand(p):
    return os.path.expanduser(p)


def safe_read(path, binary=False):
    """Return file content or None if unreadable/missing. Never raises."""
    try:
        mode = "rb" if binary else "r"
        kwargs = {} if binary else {"encoding": "utf-8", "errors": "replace"}
        with open(path, mode, **kwargs) as f:
            return f.read()
    except OSError:
        return None


def check(name, ok, detail, warn=False):
    return {"name": name, "status": "PASS" if ok else ("WARN" if warn else "FAIL"),
            "detail": detail}


def marker_hit(marker, content):
    """A marker matches if its pattern appears verbatim, or (regex:true) as a regex."""
    pattern = marker.get("pattern", "")
    if marker.get("regex"):
        return re.search(pattern, content) is not None
    return pattern in content


def load_config(cfg_path):
    """Load and validate config. Raises ConfigError on anything unusable."""
    text = safe_read(cfg_path)
    if text is None:
        raise ConfigError(f"config not readable: {cfg_path}")
    if MOJIBAKE in text:
        raise ConfigError(f"config contains replacement characters (U+FFFD) — "
                          f"saving it as UTF-8 usually fixes this: {cfg_path}")
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as e:
        raise ConfigError(f"config is not valid JSON ({cfg_path}): {e}")
    if not isinstance(raw, dict):
        raise ConfigError(f"config root must be a JSON object: {cfg_path}")

    cfg = {k: v for k, v in raw.items() if not k.startswith("_")}

    # Type/range validation — fail fast with a human-readable message
    if not isinstance(cfg.get("memory_file", ""), str):
        raise ConfigError("memory_file must be a string")
    if not cfg.get("memory_file") and not cfg.get("session_db"):
        raise ConfigError('memory_file must be a non-empty string '
                          '(or provide a "session_db" config for session-only checks)')
    try:
        cfg["char_limit"] = int(cfg.get("char_limit", 4000))
    except (TypeError, ValueError):
        raise ConfigError("char_limit must be an integer")
    if cfg["char_limit"] < 0:
        raise ConfigError("char_limit must be >= 0 (0 disables the size check)")
    for key in ("identity_files", "rules_files"):
        val = cfg.get(key, [])
        if not isinstance(val, list) or not all(
                isinstance(x, (list, tuple)) and len(x) == 2 for x in val):
            raise ConfigError(f"{key} must be a list of [path, label] pairs")
    markers = cfg.get("markers", [])
    if not isinstance(markers, list):
        raise ConfigError("markers must be a list of {pattern, label} objects")
    for m in markers:
        if not isinstance(m, dict) or not isinstance(m.get("pattern", ""), str):
            raise ConfigError("each marker must be an object with a string 'pattern'")
        if not m.get("pattern", "").strip():
            raise ConfigError("marker patterns must be non-empty "
                              "(an empty pattern matches everything)")
        if m.get("regex"):
            try:
                re.compile(m["pattern"])
            except re.error as e:
                raise ConfigError(f"marker regex invalid ({m.get('label', '?')}): {e}")
    hashes = cfg.get("known_hashes", {})
    if not isinstance(hashes, dict):
        raise ConfigError("known_hashes must be an object of path -> sha256 hex")
    try:
        cfg["staleness_days"] = int(cfg.get("staleness_days", 7))
    except (TypeError, ValueError):
        raise ConfigError("staleness_days must be an integer")
    if not isinstance(cfg.get("workspace_memory_dir", ".memory"), str):
        raise ConfigError("workspace_memory_dir must be a string")
    # session_db (v1.5): SQLite session-store health check
    sdb = cfg.get("session_db")
    if sdb is not None:
        if not isinstance(sdb, dict) or not isinstance(sdb.get("path", ""), str) or not sdb.get("path"):
            raise ConfigError('session_db must be an object with a non-empty "path"')
        tr = sdb.get("tables_required", [])
        if not isinstance(tr, list) or not all(isinstance(t, str) and t for t in tr):
            raise ConfigError("session_db.tables_required must be a list of non-empty table names")
        fr = sdb.get("freshness")
        if fr is not None:
            if not isinstance(fr, dict):
                raise ConfigError('session_db.freshness must be an object {table, column, max_stale_hours}')
            for k in ("table", "column"):
                v = fr.get(k, "")
                # identifiers are interpolated into SQL -> restrict to plain names
                if not isinstance(v, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v):
                    raise ConfigError(f"session_db.freshness.{k} must be a plain identifier (letters/digits/underscore)")
            try:
                fr["max_stale_hours"] = int(fr.get("max_stale_hours", 168))
            except (TypeError, ValueError):
                raise ConfigError("session_db.freshness.max_stale_hours must be an integer")
    return cfg


def rearchive(cfg, results):
    """Backup memory_file -> archive path. Previous archive kept as <path>.prev."""
    mem_path = expand(cfg["memory_file"])
    arch = cfg.get("archive") or {}
    ap = expand(arch.get("path", ""))
    if not ap:
        results.append(check("rearchive", False,
                             "config has no archive.path — nothing to refresh", warn=True))
        return
    mem_data = safe_read(mem_path, binary=True)
    if mem_data is None:
        results.append(check("rearchive", False,
                             f"memory file unreadable, refusing to archive: {mem_path}"))
        return
    try:
        os.makedirs(os.path.dirname(ap) or ".", exist_ok=True)
        if os.path.isfile(ap):
            os.replace(ap, ap + ".prev")  # keep one generation of history
        with open(ap, "wb") as f:
            f.write(mem_data)
        results.append(check("rearchive", True,
                             f"archived {mem_path} -> {ap}"
                             + (" (previous archive kept as .prev)" if os.path.isfile(ap + ".prev") else "")))
    except OSError as e:
        results.append(check("rearchive", False, f"archive write failed: {e}"))


def _parse_ts(val):
    """Parse a timestamp cell into unix epoch seconds, or None.

    Accepts epoch ints/floats (ms tolerated) and ISO strings. Naive datetimes are
    treated as UTC — this matches SQLite CURRENT_TIMESTAMP, which openai-agents
    SQLiteSession uses for its updated_at/created_at columns.
    """
    if isinstance(val, (int, float)):
        ts = float(val)
        return ts / 1000.0 if ts > 1e12 else ts
    s = str(val).strip()
    try:
        return float(s)
    except ValueError:
        pass
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def check_session_db(cfg, results):
    """Check 8 (v1.5) — SQLite session-store health: integrity, schema, freshness.

    Opened strictly read-only; every query is guarded so a corrupt database
    reports FAIL instead of crashing the boot check.
    """
    sdb = cfg.get("session_db") or {}
    p = expand(sdb["path"])
    label = sdb.get("label", "session store")
    if not os.path.isfile(p):
        results.append(check(f"session_db:{label}", False,
                             f"missing session database: {p}"))
        return
    try:
        conn = sqlite3.connect(f"file:{p.replace(os.sep, '/')}?mode=ro", uri=True)
    except sqlite3.Error as e:
        results.append(check(f"session_db:{label}", False,
                             f"cannot open (not a sqlite db?): {e}"))
        return
    try:
        # 8a — structural integrity: a corrupt db still deserializes, it just
        # feeds agents subtly wrong context. This is the check that catches it.
        if sdb.get("integrity", True):
            try:
                row = conn.execute("PRAGMA integrity_check").fetchone()
            except sqlite3.DatabaseError as e:
                results.append(check("session_integrity", False,
                                     f"database corrupt: {e}"))
            else:
                ok = bool(row) and str(row[0]).strip().lower() == "ok"
                results.append(check("session_integrity", ok,
                                     "PRAGMA integrity_check: ok" if ok
                                     else f"PRAGMA integrity_check: {row[0] if row else 'no result'}"))
        # 8b — schema drift: SDK migrations/renames silently break session loading
        required = sdb.get("tables_required", [])
        try:
            have = {r[0] for r in
                    conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.DatabaseError as e:
            results.append(check("session_tables", False,
                                 f"schema unreadable (corrupt db?): {e}"))
        else:
            missing = [t for t in required if t not in have]
            if missing:
                results.append(check("session_tables", False,
                                     f"missing tables {missing} — schema drift or wrong db? "
                                     f"(present: {sorted(have)})"))
            else:
                results.append(check("session_tables", True,
                                     f"{len(required)} required table(s) present"))
        # 8c — freshness decay: stale sessions mean the agent reloads outdated context
        fr = sdb.get("freshness") or {}
        if fr.get("table") and fr.get("column"):
            tbl, col, max_hours = fr["table"], fr["column"], fr.get("max_stale_hours", 168)
            try:
                row = conn.execute(f'SELECT MAX("{tbl}"."{col}") FROM "{tbl}"').fetchone()
            except sqlite3.DatabaseError as e:
                results.append(check("session_freshness", False,
                                     f"freshness query failed: {e}", warn=True))
            else:
                ts = _parse_ts(row[0]) if row else None
                if ts is None:
                    results.append(check("session_freshness", False,
                                         f"no rows / unparseable timestamp in {tbl}.{col} "
                                         f"(epoch or ISO expected)", warn=True))
                else:
                    age_h = (time.time() - ts) / 3600.0
                    stale = age_h > max_hours
                    results.append(check("session_freshness", not stale,
                                         f"newest row {age_h:.1f}h old (limit {max_hours}h)"
                                         + (" — stale: agent may be resuming outdated context"
                                            if stale else ""),
                                         warn=stale))
    finally:
        conn.close()


def run(cfg_path, workspace=None, as_json=False, state_path=None, do_rearchive=False):
    cfg = load_config(cfg_path)

    mem_path = expand(cfg["memory_file"]) if cfg.get("memory_file") else None
    limit = cfg["char_limit"]
    results = []

    # Check 1 — required files exist (identity + rules)
    for rel, label in cfg.get("identity_files", []) + cfg.get("rules_files", []):
        p = expand(rel)
        exists = os.path.isfile(p)
        size = os.path.getsize(p) if exists else 0
        results.append(check(f"file:{label}", exists,
                             f"{p} ({size}B)" if exists else f"missing: {p}"))

    # Check 2/3 — memory file checks (skipped entirely in session-only configs)
    chars, over = 0, False
    if mem_path:
        mem = safe_read(mem_path) if os.path.isfile(mem_path) else None
        markers = cfg.get("markers", [])
        if mem is None:
            results.append(check("memory_file", False,
                                 f"not found or unreadable: {mem_path}"))
        else:
            if MOJIBAKE in mem:
                results.append(check("memory_encoding", False,
                                     "memory file contains U+FFFD — it was probably not "
                                     "saved as UTF-8; fingerprint matching may silently fail",
                                     warn=True))
            missing = [m for m in markers if not marker_hit(m, mem)]
            if missing:
                labels = [f"{m.get('label', '?')} ({m['pattern'][:30]})" for m in missing]
                results.append(check("markers", False,
                                     f"missing fingerprints: {labels} — restore from archive"))
            else:
                results.append(check("markers", True,
                                     f"{len(markers)} fingerprints in place"))

        # Check 3 — memory size budget (injection dilution guard); 0 = disabled
        chars = len(mem)
        over = bool(limit) and chars > limit
        results.append(check("memory_size", not over,
                             f"{chars}/{limit} chars" + ("" if not over
                             else " — AUDIT_REQUIRED: backup -> archive -> slim -> verify"),
                             warn=over))

    # Action — --rearchive closes the "backup -> archive" step of the audit loop
    if do_rearchive:
        rearchive(cfg, results)

    # Check 4 — archive (rollback anchor): exists, non-trivial, still holds fingerprints
    arch = cfg.get("archive") or {}
    if arch.get("path"):
        ap = expand(arch["path"])
        if os.path.isfile(ap):
            size = os.path.getsize(ap)
            results.append(check(f"archive:{arch.get('label', 'backup')}", True, f"{ap} ({size}B)"))
            if size < 1024:
                results.append(check("archive_size", False, f"suspiciously small ({size}B)",
                                     warn=True))
            arch_content = safe_read(ap)
            if arch_content is None:
                results.append(check("archive_markers", False,
                                     f"archive unreadable: {ap}", warn=True))
            else:
                if MOJIBAKE in arch_content:
                    results.append(check("archive_encoding", False,
                                         f"archive contains U+FFFD — restore would corrupt "
                                         f"memory; re-save as UTF-8 or --rearchive: {ap}",
                                         warn=True))
                lost = [m.get("label", "?") for m in markers
                        if m.get("pattern", "") and not marker_hit(m, arch_content)]
                if lost:
                    results.append(check("archive_markers", False,
                                         f"archive lacks fingerprints {lost} — restoring it would "
                                         f"silently drop those conventions; re-archive first",
                                         warn=True))
                else:
                    results.append(check("archive_markers", True,
                                         f"archive still holds all {len(markers)} fingerprints"))
        else:
            results.append(check(f"archive:{arch.get('label', 'backup')}", False,
                                 f"missing rollback anchor: {ap}"))

    # Check 5 — supply-chain: known SHA256 hashes (v1.1, review Agent O/AA)
    for rel, expected in (cfg.get("known_hashes") or {}).items():
        p = expand(rel)
        if not os.path.isfile(p):
            results.append(check(f"hash:{rel}", False, f"file missing: {p}", warn=True))
            continue
        data = safe_read(p, binary=True)
        if data is None:
            results.append(check(f"hash:{rel}", False, f"file unreadable: {p}", warn=True))
            continue
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            results.append(check(f"hash:{rel}", False,
                                 f"SHA256 drifted — file changed since fingerprint (tamper or upgrade): {p}"))
        else:
            results.append(check(f"hash:{rel}", True, "SHA256 match"))

    # Check 8 (v1.5) — SQLite session stores, optional
    if cfg.get("session_db"):
        check_session_db(cfg, results)

    # Check 6 — self-check freshness (v1.1, review event "50 sessions without a check")
    if state_path:
        now = datetime.now().timestamp()
        last = None
        if os.path.isfile(state_path):
            raw_state = safe_read(state_path)
            if raw_state is not None:
                try:
                    last = float(json.loads(raw_state).get("last_run", 0))
                except (ValueError, AttributeError):
                    last = None
        stale_days = cfg["staleness_days"]
        if last is None:
            results.append(check("freshness", False,
                                 "no previous run recorded (first run?) — "
                                 "re-run regularly, boot checks rot too", warn=True))
        else:
            age_days = (now - last) / 86400
            results.append(check("freshness", age_days <= stale_days,
                                 f"last run {age_days:.1f} days ago"
                                 + ("" if age_days <= stale_days
                                    else f" — exceeds staleness_days={stale_days}, re-audit advised"),
                                 warn=age_days > stale_days))
        try:
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"last_run": now,
                           "iso": datetime.now().isoformat(timespec="seconds")}, f)
        except OSError as e:
            results.append(check("freshness_state", False,
                                 f"could not write state file ({e}) — freshness check "
                                 f"will be blind next run", warn=True))

    # Check 7 — project-level (L2) memory dir, optional
    if workspace:
        l2 = os.path.join(workspace, cfg.get("workspace_memory_dir", ".memory"))
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
        print(f"=== agent-memory-doctor v{VERSION} | {report['time']} ===")
        for r in results:
            icon = {"PASS": "[ OK ]", "WARN": "[WARN]", "FAIL": "[FAIL]"}[r["status"]]
            print(f"{icon} {r['name']} — {r['detail']}")
        print(f"=== {verdict} ===")
        if over:
            print("AUDIT_REQUIRED: memory file over limit -> backup, archive, slim, verify. "
                  "(tip: --rearchive performs the backup step)")
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
    ap.add_argument("--state", default=None,
                    help="state file recording last run (enables freshness check)")
    ap.add_argument("--rearchive", action="store_true",
                    help="refresh the archive from memory_file first (previous "
                         "archive kept as <path>.prev), then run all checks")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--init", action="store_true", help="write a config template")
    ap.add_argument("--version", action="version", version=f"agent-memory-doctor v{VERSION}")
    args = ap.parse_args()
    if args.init:
        sys.exit(init_config(args.config))
    if not os.path.isfile(args.config):
        print(f"config not found: {args.config} (run with --init to create one)")
        sys.exit(2)
    try:
        sys.exit(run(args.config, args.workspace, args.json, args.state, args.rearchive))
    except ConfigError as e:
        print(f"CONFIG ERROR: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
