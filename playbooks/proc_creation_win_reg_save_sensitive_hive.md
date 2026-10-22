# SAM, SYSTEM or SECURITY Hive Saved With reg.exe

| | |
|---|---|
| Rule | [`rules/windows/process_creation/proc_creation_win_reg_save_sensitive_hive.yml`](../rules/windows/process_creation/proc_creation_win_reg_save_sensitive_hive.yml) |
| Severity | high |
| ATT&CK | [T1003.002](https://attack.mitre.org/techniques/T1003/002/), [T1003.004](https://attack.mitre.org/techniques/T1003/004/) |
| Test samples | [`tests/data/proc_creation_win_reg_save_sensitive_hive/`](../tests/data/proc_creation_win_reg_save_sensitive_hive/) |

## What it means

Someone saved the SAM, SYSTEM or SECURITY hive to a file. With SYSTEM (boot key) and SAM, an
attacker extracts local account hashes offline; with SECURITY, LSA secrets and cached
domain logons. The recorded attack ran `reg.exe save HKLM\sam sam` from an Empire agent.

## Investigate

1. Find the output files (`reg save <hive> <file>`): location, size, and whether they
   were moved or deleted afterwards.
2. Check the parent and user. `reg save` needs administrator rights: how did this account
   get them?
3. Look for the other hives being saved in the same minute: SAM alone is useless without
   SYSTEM.
4. Check for exfiltration of the files and for later logons with the local administrator
   account on other hosts (pass-the-hash, 4624 logon type 3 with NTLM).

## False positives

- Backup or forensic collection scripts. Confirm with the owner, then filter on the
  script's full command line and account.

## Respond

- Rotate the local administrator password (LAPS makes it unique per host, which limits
  pass-the-hash).
- If SECURITY was saved, rotate service account passwords stored as LSA secrets and
  assume cached domain credentials are exposed.
- Investigate how administrator rights were obtained.
