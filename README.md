# TamperGuard
**File Integrity Monitoring with Tamper-Evident Hash-Chained Logging**
CS3002 Information Security (Fall 2026) – Term Project
Author: Muhammad Ahmad (GitHub: MuhammadAhmad59)

TamperGuard protects a folder against unauthorized changes. It stores a trusted
SHA-256 baseline of every file, detects modified / deleted / new / renamed files
and permission changes, flags ransomware-style changes (mass changes and encryption-like
content), and writes every alert
to an audit log that **cannot be silently edited** (HMAC hash chain + signed anchor).

## Requirements
* Python 3.8 or newer. **No external libraries** (standard library only).
* Tested on Windows 10 and Linux. It uses only portable Python, so it should also work on macOS (not tested).

## Files
| File | Purpose |
|---|---|
| `tamperguard.py` | the tool (CLI + library) |
| `attack_simulation.py` | 21 test scenarios (attacks, false-positive controls, known limitations), performance and latency tests |
| `demo.py` | step-by-step demo for the in-class evaluation |
| `results.json`, `results.md` | output of the last evaluation run (Windows 10) |
| `docs/` | proposal, architecture documentation and security analysis |

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
| ENCRYPTION_SUSPECTED | HIGH | a changed file went from readable (low entropy) to random-looking (high entropy) |
| RANSOMWARE_SUSPECTED | CRITICAL | several files look encrypted (default 3 or more), even if too few for MASS_CHANGE |
| LOG_TAMPERED | CRITICAL | audit log edited / truncated / deleted |
| BASELINE_TAMPERED | CRITICAL | baseline edited / deleted |

## Entropy-based ransomware detection
Encrypted data looks random: its Shannon entropy is close to 8 bits per byte, while normal text is
about 4-5. When a file changes, TamperGuard measures the entropy of its first 64 KB and compares it
with the entropy stored in the baseline. A file that goes from below 7.0 to 7.5 or above raises
`ENCRYPTION_SUSPECTED`; when 3 or more files do, it raises `RANSOMWARE_SUSPECTED`. This catches slow
or small attacks that stay below the `MASS_CHANGE` threshold.
```bash
python tamperguard.py check path/to/folder --entropy-threshold 7.5 --ransom-files 3
```
Known limits: files smaller than 1 KB are skipped (they cannot reach high entropy); files that were
already compressed or encrypted (zip, jpg, mp4) are ignored; and baselines created before this
feature have no entropy values, so run `rebaseline` once to enable it. Replacing a text file with a
legitimately compressed one can still cause a false alarm.

## Important security notes
* `tg_data/key.bin` is the secret HMAC key. **Copy it (and ideally the baseline and log)
  to a USB drive or another machine.** Anyone who has the key can forge records.
* Keep `--data` outside the protected folder (it is skipped automatically if inside).
* TamperGuard *detects* tampering; it does not prevent or undo it.

## Test results (Windows 10, Intel Core i7-10850H, 16 GB RAM, SSD)
Run `python attack_simulation.py` to reproduce. Summary of two runs (timings vary between runs):

| Measure | Result |
|---|---|
| Attacks detected | 16 of 16 (100%) |
| False alarms in 3 control scenarios | 0 |
| Known limitations confirmed | 2 (secret key theft, log rollback) |
| Scan of 1,000 files (97.7 MB) | about 1.1 to 1.2 s (two runs) |
| Detection delay in watch mode (0.5 s polling) | mean 0.54 to 0.61 s (two runs) |

The scenarios were written by the author, so these results show how the tool handles these specific
attacks; they are not an independent benchmark. Details are in `docs/SECURITY_ANALYSIS.md`.

## Documentation
* [Architecture](docs/ARCHITECTURE.md): components, log design, entropy detection, threat model
* [Security analysis](docs/SECURITY_ANALYSIS.md): results, performance, limitations, lessons learned
* [Project proposal](docs/TamperGuard_Project_Proposal.docx)

## Repository layout
```
ISProject/
  tamperguard.py            # the tool
  attack_simulation.py      # evaluation suite (21 scenarios)
  demo.py                   # live demo
  results.json, results.md  # last evaluation results
  README.md
  docs/                     # proposal, architecture, security analysis
  .gitignore                # keeps the secret key and runtime data out of Git
```
