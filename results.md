| ID | Category | Scenario | Result |
|---|---|---|---|
| S01 | Baseline behaviour | No changes (false-positive check) | NO FALSE ALARM |
| S02 | Attack on files | File content modified | DETECTED |
| S03 | Attack on files | Stealthy 1-bit change with forged size & timestamp | DETECTED |
| S04 | Attack on files | File deleted | DETECTED |
| S05 | Attack on files | Malicious file planted (web shell) | DETECTED |
| S06 | Attack on files | File renamed to hide it | DETECTED |
| S07 | Attack on files | Permissions changed (file made read-only) | DETECTED |
| S08 | Attack on files | Ransomware-style mass encryption | DETECTED |
| S09 | Attack on evidence | Log entry edited | DETECTED |
| S10 | Attack on evidence | Log entry deleted from the middle | DETECTED |
| S11 | Attack on evidence | Newest log entries truncated | DETECTED |
| S12 | Attack on evidence | Whole log file deleted | DETECTED |
| S13 | Attack on evidence | Log rewritten with re-computed plain-hash chain (no key) | DETECTED |
| S14 | Attack on evidence | Baseline hash edited to hide a changed file | DETECTED |
| S15 | Attack on evidence | Baseline file deleted | DETECTED |
| S16 | Attack on evidence | Anchor file forged to hide truncation | DETECTED |
| L01 | Known limitation | Attacker steals the secret key and re-signs everything | NOT DETECTED |
| L02 | Known limitation | Rollback: attacker restores older valid log + anchor | NOT DETECTED |
