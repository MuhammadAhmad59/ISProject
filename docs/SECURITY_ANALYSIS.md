# TamperGuard: Security Analysis

**TamperGuard: File Integrity Monitoring with Tamper-Evident Logging**
CS3002 Information Security (Fall 2026), Term Project
Author: Muhammad Ahmad (GitHub: MuhammadAhmad59)

## 1. Summary

TamperGuard was tested with an automated suite of 21 scenarios (`attack_simulation.py`): 16 attacks,
3 false-positive controls and 2 known limitations. On the test machine described below:

- **16 of 16 attacks were detected (100%)**, including attacks on the audit log and the baseline.
- **0 false alarms** in the 3 control scenarios.
- **2 limitations were confirmed** (key theft and log rollback). They are not detected, and are
  discussed honestly in section 6.
- A scan of 1,000 files (97.7 MB) took about 1.2 s, and the mean detection delay in watch mode was
  0.54 s with a 0.5 s polling interval.

All of these results were produced on the machine below and can be reproduced with
`python attack_simulation.py`. The scenarios were written by the author, so they show that the
tool handles these specific attacks. They are not an independent benchmark.

## 2. Test environment

| Item | Value |
|---|---|
| Computer | HP ZBook Studio G7 Mobile Workstation |
| CPU | Intel Core i7-10850H @ 2.70 GHz |
| RAM | 16 GB (15.8 GB usable) |
| Storage | 477 GB SSD (SK hynix PC601) |
| Operating system | Windows 10 Pro, 64-bit (build 19045) |
| Software | Python 3, standard library only |
| Date of run | 21 November 2026 |

## 3. Method

Each scenario runs in a fresh temporary folder with 20 small files. The test creates a baseline,
carries out the attack, then runs the same check a user would run and records whether the attack
was detected. Controls are scenarios where a correct tool must stay silent. Known limitations are
scenarios where an attack is expected to succeed, to show where the design stops protecting.

## 4. Results

### 4.1 Detection results

| ID | Category | Scenario | Result |
|---|---|---|---|
| S01 | Control | No changes | No false alarm |
| S02 | Attack on files | File content modified | Detected |
| S03 | Attack on files | 1-bit change with forged size and timestamp | Detected |
| S04 | Attack on files | File deleted | Detected |
| S05 | Attack on files | Malicious file planted (web shell) | Detected |
| S06 | Attack on files | File renamed to hide it | Detected (RENAMED) |
| S07 | Attack on files | Permissions changed (file made read-only) | Detected |
| S08 | Attack on files | Ransomware-style mass encryption | Detected (MASS_CHANGE) |
| S09 | Attack on evidence | Log entry edited | Detected |
| S10 | Attack on evidence | Log entry deleted from the middle | Detected |
| S11 | Attack on evidence | Newest log entries truncated | Detected |
| S12 | Attack on evidence | Whole log file deleted | Detected |
| S13 | Attack on evidence | Log rewritten with a recomputed plain SHA-256 chain (no key) | Detected |
| S14 | Attack on evidence | Baseline hash edited to hide a changed file | Detected |
| S15 | Attack on evidence | Baseline file deleted | Detected |
| S16 | Attack on evidence | Anchor file forged to hide truncation | Detected |
| S17 | Attack on files | Ransomware encrypting only 5 files, below the mass-change threshold | Detected (entropy check) |
| S18 | Control | Normal text edits to 6 documents | No false alarm |
| S19 | Control | Already-compressed archive legitimately replaced | No false alarm |
| L01 | Known limitation | Attacker steals the secret key and re-signs everything | **Not detected** |
| L02 | Known limitation | Rollback to an older valid log and anchor | **Not detected** |

### 4.2 What the results show

- **S03 (stealth change):** the attacker flips one bit and restores the file size and timestamp.
  Tools that compare only size and modification time would miss this. A content hash does not.
- **S13 (forged log):** an attacker with no key can recompute a plain hash chain, but cannot
  produce valid HMACs. This is why the log uses a keyed MAC.
- **S11 and S12 (truncation, deletion):** a chain alone cannot show that its end was removed.
  The signed anchor makes this visible.
- **S17 (entropy check):** the attacker encrypts only 5 files, which is below the MASS_CHANGE
  threshold of 10, so the older rule alone would raise no ransomware alert. The entropy check
  noticed that readable files had become random-looking, and raised ENCRYPTION_SUSPECTED and
  RANSOMWARE_SUSPECTED.
- **S18 and S19 (controls):** ordinary edits and a replaced compressed file did not raise
  ransomware alerts. These controls are important, because a detector that fires on normal work
  would be turned off by its users.

### 4.3 Performance

Measured on the machine in section 2 (one run):

| Test | Result |
|---|---|
| Creating a baseline of 1,000 files (97.7 MB) | 9.55 s |
| Full check of 1,000 files | 1.25 s (about 78 MB/s) |
| Hashing one 100 MB file | 0.33 s |
| Appending 500 log entries | 6.61 s (about 13 ms per entry) |
| Verifying a 500-entry log | 0.05 s |

Notes:

- Creating a baseline became slower after the entropy feature was added. An earlier run on the
  same machine, before that feature, took 5.76 s. The extra time is the one-off cost of measuring
  entropy for every file. Normal checks do not measure entropy for unchanged files.
- The check time also differed between runs (0.92 s earlier, 1.25 s now) even though that code path
  did not change, so these timings vary from run to run. Antivirus scanning and other programs
  running at the same time could be factors, but this was not investigated.
- Each log entry is written to disk with a forced flush so that it survives a crash. This is the
  likely reason log writes take milliseconds each, but this was not isolated by a separate test.
  For a monitoring tool that records only changes, this is acceptable.

### 4.4 Detection delay in watch mode

With a polling interval of 0.5 s, five modifications were detected after 0.235, 0.637, 0.617, 0.606
and 0.594 seconds (mean 0.54 s, maximum 0.64 s). The delay is bounded by the polling interval plus
the time to scan and hash the folder. A shorter interval gives faster alerts at the cost of more
CPU and disk reads.

## 5. Why the design resists the attacks that were tested

| Defence | Technique | Stops |
|---|---|---|
| Content hashing | SHA-256 | Edits that forge size and timestamp (S03) |
| Authenticated baseline | HMAC-SHA256 | Editing or deleting the baseline to hide changes (S14, S15) |
| Keyed hash chain | HMAC with `prev` links | Editing, deleting or re-ordering log entries (S09, S10, S13) |
| Signed anchor | HMAC over count and last MAC | Truncation, deletion, forged anchor (S11, S12, S16) |
| Entropy check | Shannon entropy of changed files | Slow ransomware that stays under the mass-change threshold (S17) |
| Rename detection | Matching hashes of deleted and new files | Hiding a file by renaming it (S06) |

## 6. Limitations

1. **Key theft (L01).** All trust rests on the secret key. An attacker who obtains `key.bin` can
   re-sign a forged baseline and log. *Mitigation:* keep the key offline (for example on a USB
   drive), restrict access to the data folder, or protect the key with a passphrase or hardware
   token.
2. **Rollback (L02).** An attacker who saved an older valid copy of the log and anchor can restore
   both, and the old state verifies correctly. *Mitigation:* ship each new anchor to another
   machine (remote log shipping, e-mail) so the latest state exists outside the attacked computer.
3. **The monitor can be stopped.** An attacker with administrator rights could stop the process or
   remove the tool. TamperGuard detects tampering after the fact. It does not prevent it.
4. **Polling gap.** A file changed and restored between two scans is not seen. Operating-system
   change notifications would close this gap.
5. **Entropy check limits.** Files under 1 KB are skipped. Files that were already compressed or
   encrypted are ignored. Replacing a text file with a legitimately compressed one can cause a
   false alarm. Baselines created before the feature have no entropy values until `rebaseline` is
   run. An attacker who encrypts slowly, or who pads encrypted data to lower its entropy, could
   still avoid the check.
6. **Windows permissions.** On Windows only the read-only flag is compared, because Windows has no
   Unix permission bits.
7. **No content analysis.** TamperGuard reports that a file changed. It does not decide whether the
   change is malicious.

## 7. Lessons learned

- A plain hash chain is not enough, because anyone can recompute it. A keyed MAC is what makes
  forging fail.
- A chain cannot prove that its end was not cut off, so a separate signed anchor is needed.
- Timestamps and sizes can be forged, so integrity checks must be based on content hashes.
- A detector must be tested for false alarms as well as for detections. The two controls S18 and
  S19 were added for this reason.
- Every security design needs an honest statement of what it does not protect against. Here, key
  management is the real weak point.

## 8. Future work

- Operating-system file notifications for instant detection.
- Remote log shipping and e-mail alerts, which would close the rollback limitation.
- Protecting the key with a passphrase or the Windows credential store.
- A small dashboard for viewing alerts.
- Better ransomware detection that combines entropy with file-extension changes and the rate of
  file changes.

## 9. Reproducing the results

```
python attack_simulation.py > output.txt 2>&1
type output.txt
```

The script prints one line per scenario and writes `results.json` and `results.md`. Performance
numbers will differ on other computers.
