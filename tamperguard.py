#!/usr/bin/env python3
"""
TamperGuard - File Integrity Monitoring with Tamper-Evident Logging
CS3002 Information Security - Term Project

What it does
------------
1. `init`        : records a baseline (SHA-256 of every file) of a protected folder.
2. `check`       : one-off scan, compares the folder with the baseline.
3. `watch`       : continuous monitoring; raises alerts in near real time.
4. `verify-log`  : verifies the tamper-evident (HMAC hash-chained) audit log.
5. `rebaseline`  : accepts the current state as the new trusted baseline.
6. `show-log`    : prints the audit log.

Security design (summary)
-------------------------
* SHA-256 detects any content change, even if size/mtime were forged.
* The baseline file is authenticated with HMAC-SHA256 (secret key).
* Every log entry carries the MAC of the previous entry (hash chain) and its own
  HMAC, so editing, deleting or re-ordering an entry breaks the chain.
* A separate signed "anchor" file stores (entry count, last MAC) so that
  truncating the end of the log or deleting the log is also detected.

Only the Python standard library is used (Python 3.8+).
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
import threading
import time
from datetime import datetime, timezone

CHUNK = 1024 * 1024
GENESIS = "0" * 64
DEFAULT_DATA = "tg_data"
DEFAULT_MASS_THRESHOLD = 10

SEVERITY = {
    "MODIFIED": "HIGH",
    "DELETED": "HIGH",
    "NEW_FILE": "MEDIUM",
    "RENAMED": "MEDIUM",
    "PERMISSION_CHANGED": "MEDIUM",
    "MASS_CHANGE": "CRITICAL",
    "LOG_TAMPERED": "CRITICAL",
    "BASELINE_TAMPERED": "CRITICAL",
    "BASELINE_CREATED": "INFO",
    "BASELINE_UPDATED": "INFO",
}
COLOR = {"CRITICAL": "\033[95m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
         "INFO": "\033[92m"}
RESET = "\033[0m"


# --------------------------------------------------------------------------
# Crypto helpers
# --------------------------------------------------------------------------
def canonical(obj):
    """Deterministic JSON encoding (so the same data always gives the same MAC)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def hmac_hex(key, data):
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def key_path(data_dir):
    return os.path.join(data_dir, "key.bin")


def load_key(data_dir, create=False):
    path = key_path(data_dir)
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    if not create:
        raise FileNotFoundError("Secret key not found in '%s'. Run `init` first." % data_dir)
    os.makedirs(data_dir, exist_ok=True)
    key = secrets.token_bytes(32)
    with open(path, "wb") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def hash_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                block = f.read(CHUNK)
                if not block:
                    break
                h.update(block)
    except (PermissionError, OSError):
        return "UNREADABLE"
    return h.hexdigest()


# --------------------------------------------------------------------------
# Scanning / baseline
# --------------------------------------------------------------------------
def scan(root, data_dir):
    """Return {relative_path: {sha256, size, mode}} for every regular file."""
    root = os.path.abspath(root)
    skip = os.path.realpath(data_dir)
    files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if os.path.realpath(os.path.join(dirpath, d)) != skip]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            try:
                st = os.stat(full)
            except OSError:
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            files[rel] = {"sha256": hash_file(full), "size": st.st_size,
                          "mode": stat.S_IMODE(st.st_mode)}
    return files


def baseline_path(data_dir):
    return os.path.join(data_dir, "baseline.json")


def save_baseline(data_dir, key, root, files):
    body = {"root": os.path.abspath(root), "created": now_iso(), "files": files}
    doc = dict(body)
    doc["mac"] = hmac_hex(key, canonical(body))
    tmp = baseline_path(data_dir) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
    os.replace(tmp, baseline_path(data_dir))


def load_baseline(data_dir, key):
    """Return (baseline_dict_or_None, ok). ok=False means missing/forged."""
    try:
        with open(baseline_path(data_dir), "r", encoding="utf-8") as f:
            doc = json.load(f)
        mac = doc.pop("mac", "")
        ok = hmac.compare_digest(mac, hmac_hex(key, canonical(doc)))
        return doc, ok
    except (OSError, ValueError):
        return None, False


# --------------------------------------------------------------------------
# Tamper-evident log
# --------------------------------------------------------------------------
class SecureLog:
    """Append-only JSON-lines log. Each entry is HMAC'd and chained to the last."""

    def __init__(self, data_dir, key):
        self.dir = data_dir
        self.key = key
        self.path = os.path.join(data_dir, "audit.log")
        self.anchor = os.path.join(data_dir, "audit.anchor")

    def _read_lines(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as f:
            return [ln for ln in f.read().split("\n") if ln.strip()]

    def entry_mac(self, entry):
        body = {k: v for k, v in entry.items() if k != "mac"}
        return hmac_hex(self.key, canonical(body))

    def append(self, event, path, details=None):
        os.makedirs(self.dir, exist_ok=True)
        lines = self._read_lines()
        prev, idx = GENESIS, len(lines)
        if lines:
            try:
                prev = json.loads(lines[-1]).get("mac", GENESIS)
            except ValueError:
                pass
        entry = {"idx": idx, "ts": now_iso(), "event": event,
                 "severity": SEVERITY.get(event, "INFO"),
                 "path": path, "details": details or {}, "prev": prev}
        entry["mac"] = self.entry_mac(entry)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._write_anchor(idx + 1, entry["mac"])
        return entry

    def _write_anchor(self, count, last_mac):
        body = {"count": count, "last_mac": last_mac}
        body["mac"] = hmac_hex(self.key, ("%d|%s" % (count, last_mac)).encode())
        with open(self.anchor, "w", encoding="utf-8") as f:
            json.dump(body, f)

    def verify(self):
        """Return a list of human-readable problems ([] means the log is intact)."""
        problems = []
        lines = self._read_lines()
        prev = GENESIS
        last_mac = GENESIS
        for i, ln in enumerate(lines):
            try:
                e = json.loads(ln)
            except ValueError:
                problems.append("entry %d: unreadable / corrupted" % i)
                continue
            if e.get("idx") != i:
                problems.append("entry %d: index mismatch (entry deleted/re-ordered?)" % i)
            if e.get("prev") != prev:
                problems.append("entry %d: broken hash chain (previous entry changed or removed)" % i)
            if not hmac.compare_digest(str(e.get("mac", "")), self.entry_mac(e)):
                problems.append("entry %d: invalid MAC (entry was edited or forged)" % i)
            prev = e.get("mac", "")
            last_mac = prev

        # check anchor (detects truncation / deletion of the log)
        try:
            with open(self.anchor, "r", encoding="utf-8") as f:
                a = json.load(f)
            good = hmac.compare_digest(
                str(a.get("mac", "")),
                hmac_hex(self.key, ("%s|%s" % (a.get("count"), a.get("last_mac"))).encode()))
            if not good:
                problems.append("anchor file: invalid MAC (anchor forged)")
            elif a["count"] != len(lines):
                problems.append("anchor says %d entries but log has %d (log truncated or entries added/removed)"
                                % (a["count"], len(lines)))
            elif a["last_mac"] != last_mac and lines:
                problems.append("anchor last-entry MAC does not match log tail")
        except (OSError, ValueError, KeyError):
            if lines or os.path.exists(self.path):
                problems.append("anchor file missing or unreadable")
            elif os.path.exists(baseline_path(self.dir)):
                problems.append("audit log is missing although a baseline exists (log deleted)")
        return problems

    def entries(self):
        out = []
        for ln in self._read_lines():
            try:
                out.append(json.loads(ln))
            except ValueError:
                out.append({"event": "CORRUPTED_LINE", "severity": "CRITICAL", "path": "", "ts": ""})
        return out


# --------------------------------------------------------------------------
# Change detection
# --------------------------------------------------------------------------
def build_events(base_files, cur_files, mass_threshold=DEFAULT_MASS_THRESHOLD):
    """Compare baseline with current state. Returns list of (event, path, details)."""
    events = []
    deleted = sorted(p for p in base_files if p not in cur_files)
    new = sorted(p for p in cur_files if p not in base_files)

    # detect renames: a deleted file and a new file with identical content
    renamed = []
    new_by_hash = {}
    for p in new:
        new_by_hash.setdefault(cur_files[p]["sha256"], []).append(p)
    still_deleted = []
    for p in deleted:
        h = base_files[p]["sha256"]
        if new_by_hash.get(h):
            target = new_by_hash[h].pop(0)
            renamed.append((p, target))
        else:
            still_deleted.append(p)
    renamed_targets = {t for _, t in renamed}
    new = [p for p in new if p not in renamed_targets]

    modified = []
    for p, b in sorted(base_files.items()):
        c = cur_files.get(p)
        if c is None:
            continue
        if c["sha256"] != b["sha256"]:
            modified.append(p)
            events.append(("MODIFIED", p, {
                "old_sha256": b["sha256"], "new_sha256": c["sha256"],
                "old_size": b["size"], "new_size": c["size"]}))
        elif c["mode"] != b["mode"]:
            events.append(("PERMISSION_CHANGED", p, {
                "old_mode": oct(b["mode"]), "new_mode": oct(c["mode"])}))
    for p in still_deleted:
        events.append(("DELETED", p, {"old_sha256": base_files[p]["sha256"]}))
    for p in new:
        events.append(("NEW_FILE", p, {"sha256": cur_files[p]["sha256"],
                                       "size": cur_files[p]["size"]}))
    for old, tgt in renamed:
        events.append(("RENAMED", old, {"new_path": tgt}))

    if len(modified) + len(still_deleted) >= mass_threshold:
        events.append(("MASS_CHANGE", "*", {
            "modified": len(modified), "deleted": len(still_deleted),
            "note": "possible ransomware / mass tampering"}))
    return events


def _enable_windows_ansi():
    """Make colour codes work in classic Windows cmd/PowerShell (no-op elsewhere)."""
    if os.name == "nt":
        os.system("")          # turns on virtual-terminal processing


_enable_windows_ansi()


def format_alert(event, path, details):
    sev = SEVERITY.get(event, "INFO")
    extra = ""
    if event == "MODIFIED":
        extra = "  sha256 %s... -> %s..." % (details["old_sha256"][:12], details["new_sha256"][:12])
    elif event == "RENAMED":
        extra = "  -> %s" % details["new_path"]
    elif event == "MASS_CHANGE":
        extra = "  (%d modified, %d deleted)" % (details["modified"], details["deleted"])
    elif event == "PERMISSION_CHANGED":
        extra = "  %s -> %s" % (details["old_mode"], details["new_mode"])
    use_color = sys.stdout.isatty()
    c, r = (COLOR.get(sev, ""), RESET) if use_color else ("", "")
    return "%s[%s] %-18s %s%s%s" % (c, sev, event, path, extra, r)


# --------------------------------------------------------------------------
# High level operations (used by the CLI and by the test-suite)
# --------------------------------------------------------------------------
def do_init(root, data_dir, force=False):
    if os.path.exists(baseline_path(data_dir)) and not force:
        raise FileExistsError("Baseline already exists. Use --force to overwrite.")
    key = load_key(data_dir, create=True)
    files = scan(root, data_dir)
    save_baseline(data_dir, key, root, files)
    log = SecureLog(data_dir, key)
    log.append("BASELINE_CREATED", os.path.abspath(root), {"files": len(files)})
    return len(files)


def do_check(root, data_dir, mass_threshold=DEFAULT_MASS_THRESHOLD, quiet=False, write_log=True):
    """One-off scan. Returns a report dict."""
    key = load_key(data_dir)
    log = SecureLog(data_dir, key)
    report = {"baseline_ok": True, "log_problems": [], "events": []}

    base, ok = load_baseline(data_dir, key)
    if not ok:
        report["baseline_ok"] = False
        report["events"].append(("BASELINE_TAMPERED", baseline_path(data_dir),
                                 {"reason": "missing or invalid MAC"}))
    report["log_problems"] = log.verify()
    if report["log_problems"]:
        report["events"].append(("LOG_TAMPERED", log.path, {"problems": report["log_problems"]}))

    if base is not None and ok:
        cur = scan(root, data_dir)
        report["events"] += build_events(base["files"], cur, mass_threshold)

    for ev in report["events"]:
        if not quiet:
            print(format_alert(*ev))
            if ev[0] == "LOG_TAMPERED":
                for p in ev[2]["problems"]:
                    print("         - " + p)
        if write_log:
            log.append(*ev)
    report["exit_code"] = (2 if (not report["baseline_ok"] or report["log_problems"])
                           else (1 if report["events"] else 0))
    return report


def watch_loop(root, data_dir, interval=2.0, mass_threshold=DEFAULT_MASS_THRESHOLD,
               stop=None, callback=None, quiet=False):
    """Continuously monitor. Each distinct change is reported/logged once."""
    key = load_key(data_dir)
    log = SecureLog(data_dir, key)
    base, ok = load_baseline(data_dir, key)
    if not ok or base is None:
        raise SystemExit("Baseline is missing or has been tampered with - refusing to start.")
    trusted = base["files"]            # in-memory trusted copy
    reported = set()
    cycle = 0

    def emit(ev):
        if not quiet:
            print(format_alert(*ev))
            if ev[0] == "LOG_TAMPERED":
                for p in ev[2]["problems"]:
                    print("         - " + p)
        log.append(*ev)
        if callback:
            callback(ev, time.time())

    while not (stop is not None and stop.is_set()):
        cycle += 1
        active = {}
        cur = scan(root, data_dir)
        for ev in build_events(trusted, cur, mass_threshold):
            active[json.dumps([ev[0], ev[1], ev[2]], sort_keys=True)] = ev
        # integrity of our own evidence (reported once, then remembered)
        _, bok = load_baseline(data_dir, key)
        if not bok:
            active["BASELINE_TAMPERED"] = ("BASELINE_TAMPERED", baseline_path(data_dir),
                                           {"reason": "baseline file modified on disk"})
        if cycle % 5 == 1:
            probs = log.verify()
            if probs:
                active["LOG_TAMPERED"] = ("LOG_TAMPERED", log.path, {"problems": probs})
        for sig, ev in active.items():
            if sig not in reported:
                emit(ev)
        sticky = {s for s in reported if s in ("LOG_TAMPERED", "BASELINE_TAMPERED")}
        reported = set(active.keys()) | sticky
        # sleep in small steps so stop requests are honoured quickly
        slept = 0.0
        while slept < interval and not (stop is not None and stop.is_set()):
            time.sleep(min(0.05, interval))
            slept += 0.05


def do_rebaseline(root, data_dir):
    key = load_key(data_dir)
    log = SecureLog(data_dir, key)
    problems = log.verify()
    if problems:
        raise SystemExit("Refusing to rebaseline: audit log is not intact:\n  " + "\n  ".join(problems))
    files = scan(root, data_dir)
    save_baseline(data_dir, key, root, files)
    log.append("BASELINE_UPDATED", os.path.abspath(root), {"files": len(files)})
    return len(files)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None):
    p = argparse.ArgumentParser(prog="tamperguard",
                                description="File integrity monitor with tamper-evident logging")
    p.add_argument("--data", default=DEFAULT_DATA,
                   help="folder for key, baseline and log (default: ./%s)" % DEFAULT_DATA)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create baseline for a folder")
    s.add_argument("folder"); s.add_argument("--force", action="store_true")
    s = sub.add_parser("check", help="scan once and report changes")
    s.add_argument("folder"); s.add_argument("--mass-threshold", type=int, default=DEFAULT_MASS_THRESHOLD)
    s = sub.add_parser("watch", help="monitor continuously (Ctrl+C to stop)")
    s.add_argument("folder"); s.add_argument("--interval", type=float, default=2.0)
    s.add_argument("--mass-threshold", type=int, default=DEFAULT_MASS_THRESHOLD)
    s = sub.add_parser("rebaseline", help="accept current state as the new baseline")
    s.add_argument("folder")
    sub.add_parser("verify-log", help="verify integrity of the audit log")
    s = sub.add_parser("show-log", help="print audit log entries")
    s.add_argument("-n", type=int, default=20, help="number of latest entries")

    a = p.parse_args(argv)

    if a.cmd == "init":
        n = do_init(a.folder, a.data, a.force)
        print("Baseline created: %d files recorded. Data stored in '%s'." % (n, a.data))
        print("IMPORTANT: keep a copy of '%s' somewhere safe/offline." % key_path(a.data))
    elif a.cmd == "check":
        r = do_check(a.folder, a.data, a.mass_threshold)
        if not r["events"]:
            print("OK - no changes detected, baseline and log are intact.")
        return r["exit_code"]
    elif a.cmd == "watch":
        print("Watching '%s' every %.1fs - press Ctrl+C to stop." % (a.folder, a.interval))
        try:
            watch_loop(a.folder, a.data, a.interval, a.mass_threshold)
        except KeyboardInterrupt:
            print("\nStopped.")
    elif a.cmd == "rebaseline":
        n = do_rebaseline(a.folder, a.data)
        print("Baseline updated (%d files)." % n)
    elif a.cmd == "verify-log":
        key = load_key(a.data)
        probs = SecureLog(a.data, key).verify()
        if probs:
            print("LOG TAMPERED:")
            for x in probs:
                print("  - " + x)
            return 2
        print("Log integrity OK.")
    elif a.cmd == "show-log":
        key = load_key(a.data)
        for e in SecureLog(a.data, key).entries()[-a.n:]:
            print("%s  #%s  %-8s %-18s %s" % (e.get("ts", ""), e.get("idx", "?"),
                                              e.get("severity", ""), e.get("event", ""), e.get("path", "")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
