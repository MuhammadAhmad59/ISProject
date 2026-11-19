#!/usr/bin/env python3
"""
Interactive 2-minute demo for the in-class evaluation.
Press ENTER to move between steps.   Usage: python demo.py
"""
import os, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
TG = [sys.executable, os.path.join(HERE, "tamperguard.py"), "--data", "demo_data"]
ROOT = "demo_folder"


def step(title, cmd=None, action=None):
    input("\n>>> %s   [ENTER]" % title)
    if action:
        action()
    if cmd:
        print("$ tamperguard " + " ".join(cmd))
        subprocess.run(TG + cmd)


def setup():
    shutil.rmtree(ROOT, ignore_errors=True); shutil.rmtree("demo_data", ignore_errors=True)
    os.makedirs(ROOT)
    open(os.path.join(ROOT, "report.txt"), "w").write("Quarterly report - confidential\n")
    open(os.path.join(ROOT, "config.ini"), "w").write("admin=alice\nport=8080\n")
    open(os.path.join(ROOT, "notes.txt"), "w").write("meeting notes\n")


def edit():   open(os.path.join(ROOT, "config.ini"), "a").write("admin=attacker\n")
def plant():  open(os.path.join(ROOT, "shell.php"), "w").write("<?php system($_GET['c']); ?>")
def delete(): os.remove(os.path.join(ROOT, "notes.txt"))
def hide():
    p = os.path.join("demo_data", "audit.log")
    t = open(p).read().replace("MODIFIED", "BASELINE_UPDATED", 1)
    open(p, "w").write(t)


setup()
print("TamperGuard demo - protecting folder '%s'" % ROOT)
step("1. Create trusted baseline (SHA-256 of every file)", ["init", ROOT])
step("2. Nothing changed -> no false alarm", ["check", ROOT])
step("3. Attacker edits config.ini, plants a web shell, deletes notes.txt", ["check", ROOT],
     action=lambda: (edit(), plant(), delete()))
step("4. Show the tamper-evident audit log", ["show-log"])
step("5. Log is intact?", ["verify-log"])
step("6. Attacker edits the log to hide the MODIFIED alert...", ["verify-log"], action=hide)
print("\nDemo finished. (Run `python attack_simulation.py` for the full 18-scenario evaluation.)")
