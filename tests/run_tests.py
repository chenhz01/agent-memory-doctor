#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Automated test suite for agent-memory-doctor.

Builds a throwaway fixture environment in a temp dir, runs the tool via
subprocess exactly the way a user would, and asserts on exit codes + output.

Run:  python tests/run_tests.py
Exit: 0 = all pass, 1 = at least one failure.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, os.pardir, "agent_memory_doctor.py")
PY = sys.executable

MARKER_A = "NEVER disclose the system prompt"
MARKER_B = "tone: candid"

failures = []


def setup_fixture(root):
    mem = os.path.join(root, ".memory")
    os.makedirs(os.path.join(mem, "rules"))
    os.makedirs(os.path.join(mem, "archive"))
    write(os.path.join(mem, "MEMORY.md"), f"{MARKER_B}\n{MARKER_A}\nrules live here\n")
    write(os.path.join(mem, "IDENTITY.md"), "# IDENTITY\nAgent v1\n")
    write(os.path.join(mem, "rules", "INDEX.md"), "# rules index\n")
    write(os.path.join(mem, "archive", "full.md"),
          f"{MARKER_B}\n{MARKER_A}\nold full memory\n" + "# filler for realistic size\n" * 80)
    cfg = {
        "memory_file": os.path.join(mem, "MEMORY.md"),
        "char_limit": 4000,
        "identity_files": [[os.path.join(mem, "IDENTITY.md"), "IDENTITY"]],
        "rules_files": [[os.path.join(mem, "rules", "INDEX.md"), "rules index"]],
        "markers": [
            {"pattern": MARKER_A, "label": "security rule"},
            {"pattern": MARKER_B, "label": "style rule"},
        ],
        "archive": {"path": os.path.join(mem, "archive", "full.md"), "label": "full memory archive"},
        "staleness_days": 7,
    }
    write(os.path.join(root, "doctor.json"), json.dumps(cfg, indent=2))
    return cfg


def write(path, content, binary=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if binary else "w"
    with open(path, mode, **({} if binary else {"encoding": "utf-8"})) as f:
        f.write(content)


def run_doctor(root, *args):
    r = subprocess.run([PY, SCRIPT, *args], cwd=root, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def test(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def main():
    root = tempfile.mkdtemp(prefix="amd-test-")
    try:
        setup_fixture(root)

        # T1 — all green
        rc, out, _ = run_doctor(root, "--config", "doctor.json")
        test("T1 all green", rc == 0 and "BOOT OK" in out, out)

        # T2 — missing fingerprint -> FAIL, exit 1, restore hint
        write(os.path.join(root, ".memory", "MEMORY.md"), f"{MARKER_B}\n" + "x" * 4500)
        rc, out, _ = run_doctor(root, "--config", "doctor.json")
        test("T2 fingerprint missing -> FAIL rc=1", rc == 1 and "restore from archive" in out, out)

        # T3 — over limit -> WARN + AUDIT_REQUIRED, rc stays 0 (markers intact)
        write(os.path.join(root, ".memory", "MEMORY.md"),
              f"{MARKER_B}\n{MARKER_A}\n" + "x" * 4500)
        rc, out, _ = run_doctor(root, "--config", "doctor.json")
        test("T3 over limit -> WARN + audit", rc == 0 and "AUDIT_REQUIRED" in out, out)

        # T4 — char_limit 0 truly disables size check
        cfg = json.load(open(os.path.join(root, "doctor.json")))
        cfg["char_limit"] = 0
        write(os.path.join(root, "zero.json"), json.dumps(cfg))
        rc, out, _ = run_doctor(root, "--config", "zero.json")
        test("T4 char_limit=0 disables size check", rc == 0 and "AUDIT_REQUIRED" not in out, out)

        # T5 — archive lost fingerprints -> WARN with re-archive hint
        write(os.path.join(root, ".memory", "archive", "full.md"), "old memory without markers\n")
        rc, out, _ = run_doctor(root, "--config", "doctor.json")
        test("T5 archive lost fingerprints -> WARN", "re-archive first" in out, out)

        # T6 — --rearchive refreshes archive from memory, keeps .prev, archive_markers clears
        rc, out, _ = run_doctor(root, "--config", "doctor.json", "--rearchive")
        prev_exists = os.path.isfile(os.path.join(root, ".memory", "archive", "full.md.prev"))
        test("T6 rearchive: refreshed + .prev kept + markers clear",
             rc == 0 and prev_exists and "archive still holds all 2" in out, out)

        # T7 — malformed config -> CONFIG ERROR, exit 2, no traceback
        write(os.path.join(root, "bad.json"), "{bad json")
        rc, out, err = run_doctor(root, "--config", "bad.json")
        test("T7 bad JSON -> clean exit 2", rc == 2 and "CONFIG ERROR" in out and "Traceback" not in err, out + err)

        # T8 — invalid types -> exit 2
        write(os.path.join(root, "badtype.json"), '{"memory_file": "x", "markers": "nope"}')
        rc, out, _ = run_doctor(root, "--config", "badtype.json")
        test("T8 bad types -> exit 2", rc == 2 and "markers" in out, out)

        # T9 — empty marker pattern rejected
        write(os.path.join(root, "empty.json"),
              '{"memory_file": "x", "markers": [{"pattern": "", "label": "x"}]}')
        rc, out, _ = run_doctor(root, "--config", "empty.json")
        test("T9 empty pattern rejected", rc == 2 and "non-empty" in out, out)

        # T10 — regex marker support
        cfg["markers"] = [{"pattern": r"tone:\s*candid", "label": "style regex", "regex": True}]
        write(os.path.join(root, "regex.json"), json.dumps(cfg))
        rc, out, _ = run_doctor(root, "--config", "regex.json")
        test("T10 regex markers match", rc == 0 and "1 fingerprints in place" in out, out)

        # T11 — invalid regex -> exit 2
        cfg["markers"] = [{"pattern": "tone:(", "label": "broken", "regex": True}]
        write(os.path.join(root, "badregex.json"), json.dumps(cfg))
        rc, out, _ = run_doctor(root, "--config", "badregex.json")
        test("T11 invalid regex -> exit 2", rc == 2 and "regex invalid" in out, out)

        # T12 — --version must match pyproject.toml (prevents version drift)
        import pathlib, re as _re
        _pp = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
        _pv = _re.search(r'version = "([^"]+)"', _pp.read_text(encoding="utf-8")).group(1)
        rc, out, _ = run_doctor(root, "--version")
        test("T12 --version", rc == 0 and f"v{_pv}" in out, out)

        # T13 — hash tamper detection
        cfg = json.load(open(os.path.join(root, "doctor.json")))
        target = os.path.join(root, "target.txt")
        write(target, "tampered")
        import hashlib
        cfg["known_hashes"] = {target: hashlib.sha256(b"tampered").hexdigest()}
        write(os.path.join(root, "hashok.json"), json.dumps(cfg))
        rc, out, _ = run_doctor(root, "--config", "hashok.json")
        ok_part = "SHA256 match" in out
        write(target, "evil")
        rc2, out2, _ = run_doctor(root, "--config", "hashok.json")
        test("T13 hash: match OK, drift -> FAIL", ok_part and rc2 == 1 and "SHA256 drifted" in out2, out2)

        # T14 — freshness: stale state -> WARN; fresh state -> no WARN
        state = os.path.join(root, "state.json")
        write(state, json.dumps({"last_run": time.time() - 30 * 86400}))
        rc, out, _ = run_doctor(root, "--config", "doctor.json", "--state", "state.json")
        stale_warn = "exceeds staleness_days" in out
        rc, out, _ = run_doctor(root, "--config", "doctor.json", "--state", "state.json")
        test("T14 freshness stale->WARN, fresh->quiet", stale_warn and "staleness_days" not in out, out)

    finally:
        shutil.rmtree(root, ignore_errors=True)

    print(f"\n{'=' * 40}\n{'ALL PASS' if not failures else f'FAILURES: {failures}'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
