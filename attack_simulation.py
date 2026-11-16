#!/usr/bin/env python3
"""
Attack simulation & evaluation for TamperGuard.

Runs 18 scenarios (attacks on monitored files, attacks on the evidence itself,
and two *known limitations*) plus a performance benchmark and a detection-latency
test. Results are printed and saved to results.json / results.md.

Usage:  python attack_simulation.py
"""
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import time

import tamperguard as tg


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def _rm(path):
    """rmtree that also removes read-only files (needed on Windows)."""
    def onerr(func, p, exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    shutil.rmtree(path, onerror=onerr)


def make_workspace(n_files=20):
    base = tempfile.mkdtemp(prefix="tg_test_")
    root = os.path.join(base, "protected")
    data = os.path.join(base, "tg_data")
    os.makedirs(os.path.join(root, "sub"))
    for i in range(n_files):
        folder = root if i % 2 == 0 else os.path.join(root, "sub")
        with open(os.path.join(folder, "file%02d.txt" % i), "w") as f:
            f.write("original content of file %d\n" % i * 20)
    tg.do_init(root, data)
    return base, root, data


def kinds(report):
    return sorted({e[0] for e in report["events"]})


def check(root, data):
    return tg.do_check(root, data, quiet=True, write_log=True)


def tamper_log_entry(data, line_no, mutate):
    path = os.path.join(data, "audit.log")
    lines = open(path).read().split("\n")
    lines = [l for l in lines if l.strip()]
    e = json.loads(lines[line_no])
    mutate(e)
    lines[line_no] = json.dumps(e, sort_keys=True)
    open(path, "w").write("\n".join(lines) + "\n")


# ----------------------------------------------------------------------------
# scenarios: each returns (detected: bool, observed: str)
# ----------------------------------------------------------------------------
def s_clean(root, data):
    r = check(root, data)
    return (r["exit_code"] == 0), "no alerts" if r["exit_code"] == 0 else str(kinds(r))


def s_modify(root, data):
    with open(os.path.join(root, "file00.txt"), "a") as f:
        f.write("backdoor\n")
    r = check(root, data)
    return "MODIFIED" in kinds(r), str(kinds(r))


def s_stealth_modify(root, data):
    """Change content but keep identical size and timestamp (defeats mtime/size checks)."""
    p = os.path.join(root, "file02.txt")
    st = os.stat(p)
    data_bytes = bytearray(open(p, "rb").read())
    data_bytes[0] ^= 0x01                      # flip a single bit
    open(p, "wb").write(bytes(data_bytes))
    os.utime(p, (st.st_atime, st.st_mtime))    # forge timestamps
    assert os.stat(p).st_size == st.st_size
    r = check(root, data)
    return "MODIFIED" in kinds(r), "single-bit flip, size+mtime forged -> " + str(kinds(r))


def s_delete(root, data):
    os.remove(os.path.join(root, "file04.txt"))
    r = check(root, data)
    return "DELETED" in kinds(r), str(kinds(r))


def s_new_file(root, data):
    open(os.path.join(root, "shell.php"), "w").write("<?php system($_GET['c']); ?>")
    r = check(root, data)
    return "NEW_FILE" in kinds(r), str(kinds(r))


def s_rename(root, data):
    os.rename(os.path.join(root, "file06.txt"), os.path.join(root, "innocent.dat"))
    r = check(root, data)
    return "RENAMED" in kinds(r), str(kinds(r))


def s_permission(root, data):
    # 0o444 = read-only: changes the mode on Windows (which only has a read-only flag) and Linux
    os.chmod(os.path.join(root, "file08.txt"), 0o444)
    r = check(root, data)
    return "PERMISSION_CHANGED" in kinds(r), str(kinds(r))


def s_ransomware(root, data):
    """Encrypt (XOR) every file like ransomware would."""
    for dp, _, fs in os.walk(root):
        for n in fs:
            p = os.path.join(dp, n)
            b = open(p, "rb").read()
            open(p, "wb").write(bytes(x ^ 0x5A for x in b))
            os.rename(p, p + ".locked")
    r = check(root, data)
    return "MASS_CHANGE" in kinds(r), str(kinds(r))


def s_log_edit(root, data):
    check_mod = s_modify(root, data)          # create a real event first
    tamper_log_entry(data, 1, lambda e: e.update(event="NOTHING_TO_SEE", path="-"))
    probs = tg.SecureLog(data, tg.load_key(data)).verify()
    return bool(probs), "; ".join(probs[:2])


def s_log_delete_entry(root, data):
    s_modify(root, data)
    s_delete(root, data)
    path = os.path.join(data, "audit.log")
    lines = [l for l in open(path).read().split("\n") if l.strip()]
    del lines[1]                                # attacker removes the MODIFIED alert
    open(path, "w").write("\n".join(lines) + "\n")
    probs = tg.SecureLog(data, tg.load_key(data)).verify()
    return bool(probs), "; ".join(probs[:2])


def s_log_truncate(root, data):
    s_modify(root, data)
    s_delete(root, data)
    path = os.path.join(data, "audit.log")
    lines = [l for l in open(path).read().split("\n") if l.strip()]
    open(path, "w").write("\n".join(lines[:-2]) + "\n")   # remove newest 2 entries
    probs = tg.SecureLog(data, tg.load_key(data)).verify()
    return bool(probs), "; ".join(probs[:2])


def s_log_wipe(root, data):
    s_modify(root, data)
    os.remove(os.path.join(data, "audit.log"))
    probs = tg.SecureLog(data, tg.load_key(data)).verify()
    return bool(probs), "; ".join(probs[:2])


def s_log_forge_chain(root, data):
    """Attacker rewrites the whole log and recomputes a plain SHA-256 chain (no key)."""
    s_modify(root, data)
    path = os.path.join(data, "audit.log")
    prev = tg.GENESIS
    out = []
    for i, ln in enumerate([l for l in open(path).read().split("\n") if l.strip()]):
        e = json.loads(ln)
        if i == 1:
            e.update(event="BASELINE_UPDATED", severity="INFO", details={})
        e["idx"], e["prev"] = i, prev
        e.pop("mac", None)
        e["mac"] = hashlib.sha256(tg.canonical(e)).hexdigest()   # no secret key!
        prev = e["mac"]
        out.append(json.dumps(e, sort_keys=True))
    open(path, "w").write("\n".join(out) + "\n")
    probs = tg.SecureLog(data, tg.load_key(data)).verify()
    return bool(probs), "; ".join(probs[:2])


def s_baseline_edit(root, data):
    """Attacker modifies a file AND edits the baseline hash so the file looks clean."""
    p = os.path.join(root, "file10.txt")
    open(p, "a").write("evil")
    new_hash = tg.hash_file(p)
    bp = tg.baseline_path(data)
    doc = json.load(open(bp))
    doc["files"]["file10.txt"]["sha256"] = new_hash
    json.dump(doc, open(bp, "w"))
    r = check(root, data)
    return (not r["baseline_ok"]) and "BASELINE_TAMPERED" in kinds(r), str(kinds(r))


def s_baseline_delete(root, data):
    os.remove(tg.baseline_path(data))
    r = check(root, data)
    return "BASELINE_TAMPERED" in kinds(r), str(kinds(r))


def s_anchor_forge(root, data):
    s_modify(root, data)
    ap = os.path.join(data, "audit.anchor")
    a = json.load(open(ap))
    a["count"] -= 1                      # pretend there is one entry less
    json.dump(a, open(ap, "w"))
    probs = tg.SecureLog(data, tg.load_key(data)).verify()
    return bool(probs), "; ".join(probs[:2])


def s_key_compromise(root, data):
    """LIMITATION: attacker who steals the secret key can forge everything."""
    key = tg.load_key(data)
    p = os.path.join(root, "file12.txt")
    open(p, "a").write("evil")
    files = tg.scan(root, data)
    tg.save_baseline(data, key, root, files)            # attacker re-signs baseline
    r = check(root, data)
    return r["exit_code"] != 0, "attacker with key re-signed baseline -> " + (str(kinds(r)) if r["events"] else "no alerts (UNDETECTED)")


def s_rollback(root, data):
    """LIMITATION: attacker restores an old copy of log+anchor (rollback)."""
    lp, ap = os.path.join(data, "audit.log"), os.path.join(data, "audit.anchor")
    old_log, old_anchor = open(lp).read(), open(ap).read()
    s_modify(root, data)                                 # evidence gets logged...
    open(lp, "w").write(old_log)                         # ...attacker rolls it back
    open(ap, "w").write(old_anchor)
    probs = tg.SecureLog(data, tg.load_key(data)).verify()
    return bool(probs), ("rollback to older valid copy -> " + ("; ".join(probs[:2]) if probs else "no alerts (UNDETECTED)"))


SCENARIOS = [
    # (id, category, description, function, expected_detect)
    ("S01", "Baseline behaviour", "No changes (false-positive check)", s_clean, True),
    ("S02", "Attack on files", "File content modified", s_modify, True),
    ("S03", "Attack on files", "Stealthy 1-bit change with forged size & timestamp", s_stealth_modify, True),
    ("S04", "Attack on files", "File deleted", s_delete, True),
    ("S05", "Attack on files", "Malicious file planted (web shell)", s_new_file, True),
    ("S06", "Attack on files", "File renamed to hide it", s_rename, True),
    ("S07", "Attack on files", "Permissions changed (file made read-only)", s_permission, True),
    ("S08", "Attack on files", "Ransomware-style mass encryption", s_ransomware, True),
    ("S09", "Attack on evidence", "Log entry edited", s_log_edit, True),
    ("S10", "Attack on evidence", "Log entry deleted from the middle", s_log_delete_entry, True),
    ("S11", "Attack on evidence", "Newest log entries truncated", s_log_truncate, True),
    ("S12", "Attack on evidence", "Whole log file deleted", s_log_wipe, True),
    ("S13", "Attack on evidence", "Log rewritten with re-computed plain-hash chain (no key)", s_log_forge_chain, True),
    ("S14", "Attack on evidence", "Baseline hash edited to hide a changed file", s_baseline_edit, True),
    ("S15", "Attack on evidence", "Baseline file deleted", s_baseline_delete, True),
    ("S16", "Attack on evidence", "Anchor file forged to hide truncation", s_anchor_forge, True),
    ("L01", "Known limitation", "Attacker steals the secret key and re-signs everything", s_key_compromise, False),
    ("L02", "Known limitation", "Rollback: attacker restores older valid log + anchor", s_rollback, False),
]


# ----------------------------------------------------------------------------
# performance
# ----------------------------------------------------------------------------
def benchmark():
    res = {}
    base = tempfile.mkdtemp(prefix="tg_perf_")
    root, data = os.path.join(base, "p"), os.path.join(base, "d")
    os.makedirs(root)
    blob = os.urandom(100 * 1024)
    N = 1000
    for i in range(N):
        d = os.path.join(root, "d%d" % (i % 20))
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "f%d.bin" % i), "wb").write(blob)
    t = time.time(); tg.do_init(root, data); res["init_1000_files_100KB_s"] = round(time.time() - t, 3)
    t = time.time(); tg.do_check(root, data, quiet=True, write_log=False)
    res["check_1000_files_100KB_s"] = round(time.time() - t, 3)
    total_mb = N * 100 / 1024
    res["data_scanned_MB"] = round(total_mb, 1)
    res["throughput_MB_per_s"] = round(total_mb / res["check_1000_files_100KB_s"], 1)
    # large single file
    big = os.path.join(root, "big.bin")
    with open(big, "wb") as f:
        for _ in range(100):
            f.write(os.urandom(1024 * 1024))
    t = time.time(); tg.hash_file(big)
    res["hash_100MB_file_s"] = round(time.time() - t, 3)
    os.remove(big)
    # log append + verify cost
    log = tg.SecureLog(data, tg.load_key(data))
    t = time.time()
    for i in range(500):
        log.append("MODIFIED", "x%d" % i, {"i": i})
    res["log_append_500_entries_s"] = round(time.time() - t, 3)
    t = time.time(); probs = log.verify()
    res["log_verify_500_entries_s"] = round(time.time() - t, 4)
    res["log_verify_ok"] = (probs == [])
    _rm(base)
    return res


def latency(interval=0.5, trials=5):
    base, root, data = make_workspace(20)
    seen = {}
    stop = threading.Event()

    def cb(ev, ts):
        seen.setdefault(ev[1], ts)

    th = threading.Thread(target=tg.watch_loop, args=(root, data, interval, 10, stop, cb, True))
    th.start()
    time.sleep(interval * 2)
    lat = []
    for i in range(trials):
        name = "file%02d.txt" % (i * 2)
        t0 = time.time()
        with open(os.path.join(root, name), "a") as f:
            f.write("x")
        deadline = t0 + 10
        while name not in seen and time.time() < deadline:
            time.sleep(0.005)
        lat.append(round(seen.get(name, deadline) - t0, 3))
    stop.set(); th.join()
    _rm(base)
    return {"poll_interval_s": interval, "latencies_s": lat,
            "mean_latency_s": round(sum(lat) / len(lat), 3), "max_latency_s": max(lat)}


# ----------------------------------------------------------------------------
def main():
    results = []
    print("=" * 78)
    print("TamperGuard attack simulation")
    print("=" * 78)
    for sid, cat, desc, fn, expect in SCENARIOS:
        base, root, data = make_workspace()
        try:
            detected, obs = fn(root, data)
        except Exception as ex:                      # pragma: no cover
            detected, obs = False, "ERROR: %r" % ex
        _rm(base)
        outcome = "DETECTED" if detected else "NOT DETECTED"
        if sid == "S01":
            outcome = "NO FALSE ALARM" if detected else "FALSE ALARM"
        passed = (detected == expect)
        results.append({"id": sid, "category": cat, "scenario": desc, "outcome": outcome,
                        "as_expected": passed, "observed": obs})
        print("%s  %-9s %-62s %s" % (sid, "[PASS]" if passed else "[FAIL]", desc[:62], outcome))

    perf = benchmark()
    lat = latency()
    attacks = [r for r in results if r["id"].startswith("S") and r["id"] != "S01"]
    det = sum(1 for r in attacks if r["outcome"] == "DETECTED")
    summary = {"attack_scenarios": len(attacks), "detected": det,
               "detection_rate_pct": round(100.0 * det / len(attacks), 1),
               "false_positives_on_clean_run": 0 if results[0]["outcome"] == "NO FALSE ALARM" else 1,
               "all_as_expected": all(r["as_expected"] for r in results)}
    print("-" * 78)
    print("Detection rate: %d/%d (%.1f%%)   | known limitations demonstrated: 2"
          % (det, len(attacks), summary["detection_rate_pct"]))
    print("Performance:", json.dumps(perf))
    print("Latency    :", json.dumps(lat))

    out = {"summary": summary, "scenarios": results, "performance": perf, "latency": lat}
    here = os.path.dirname(os.path.abspath(__file__))
    json.dump(out, open(os.path.join(here, "results.json"), "w"), indent=2)

    with open(os.path.join(here, "results.md"), "w") as f:
        f.write("| ID | Category | Scenario | Result |\n|---|---|---|---|\n")
        for r in results:
            f.write("| %s | %s | %s | %s |\n" % (r["id"], r["category"], r["scenario"], r["outcome"]))
    return 0 if summary["all_as_expected"] else 1


if __name__ == "__main__":
    sys.exit(main())
