# TamperGuard
**File Integrity Monitoring with Tamper-Evident Hash-Chained Logging**
CS3002 Information Security (Fall 2026) – Term Project

TamperGuard protects a folder against unauthorized changes. It stores a trusted
SHA-256 baseline of every file, detects modified / deleted / new / renamed files
and permission changes, flags ransomware-style mass changes, and writes every alert
to an audit log that **cannot be silently edited** (HMAC hash chain + signed anchor).

## Requirements
* Python 3.8 or newer. **No external libraries** (standard library only).
* Works on Windows, Linux, macOS.

## Files
| File | Purpose |
|---|---|
| `tamperguard.py` | the tool (CLI + library) |
| `attack_simulation.py` | 18 attack scenarios, performance and latency tests |
| `demo.py` | step-by-step demo for the in-class evaluation |
| `results.json`, `results.md` | output of the last evaluation run |

## Windows quick start (PowerShell or cmd)
```powershell
cd C:\path\to\TamperGuard
python --version                      # must be 3.8+  (if "python" is not found, use: py)
mkdir test_folder
echo hello > test_folder\a.txt
python tamperguard.py init test_folder
echo changed >> test_folder\a.txt
python tamperguard.py check test_folder
python demo.py
python attack_simulation.py
```
Notes: put paths that contain spaces in "quotes". Windows Defender may briefly scan the files
created by `attack_simulation.py` (it simulates ransomware by renaming files to `.locked` inside a
temporary folder) - this is harmless; allow it if prompted. On Windows the "permission" check
detects the read-only flag only (Windows has no Unix permission bits).

## How to run
```bash
# 1. create the baseline of the folder you want to protect
python tamperguard.py init  path/to/folder

# 2a. one-off check (exit code: 0 clean, 1 changes found, 2 evidence tampered)
python tamperguard.py check path/to/folder

# 2b. or continuous monitoring (Ctrl+C to stop)
python tamperguard.py watch path/to/folder --interval 2

# 3. verify the audit log / read it
python tamperguard.py verify-log
python tamperguard.py show-log -n 20

# 4. after you made *legitimate* changes, accept them as the new baseline
python tamperguard.py rebaseline path/to/folder
```
Options: `--data DIR` (where key/baseline/log are kept, default `./tg_data`, placed
before the sub-command), `--mass-threshold N` (default 10 changed files triggers a
MASS_CHANGE / ransomware alert).

### Run the demo and the evaluation
```bash
python demo.py                 # interactive demo (press ENTER at each step)
python attack_simulation.py    # runs all attack scenarios + benchmarks
```

## Alert types
| Event | Severity | Meaning |
|---|---|---|
| MODIFIED | HIGH | file content changed (hash differs) |
| DELETED | HIGH | file missing |
| NEW_FILE | MEDIUM | unknown file appeared |
| RENAMED | MEDIUM | same content under a new name |
| PERMISSION_CHANGED | MEDIUM | file mode changed |
| MASS_CHANGE | CRITICAL | many files changed at once (ransomware pattern) |
| LOG_TAMPERED | CRITICAL | audit log edited / truncated / deleted |
| BASELINE_TAMPERED | CRITICAL | baseline edited / deleted |

## Important security notes
* `tg_data/key.bin` is the secret HMAC key. **Copy it (and ideally the baseline and log)
  to a USB drive or another machine.** Anyone who has the key can forge records.
* Keep `--data` outside the protected folder (it is skipped automatically if inside).
* TamperGuard *detects* tampering; it does not prevent or undo it.

## Repository layout
```
TamperGuard/
  tamperguard.py          # the tool
  attack_simulation.py    # evaluation suite
  demo.py                 # live demo
  README.md
  docs/                   # proposal and project documentation
  .gitignore              # keeps the secret key and runtime data out of Git
```
