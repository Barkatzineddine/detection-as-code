# Scheduled Task Created With a Suspicious Action or SYSTEM Context

| | |
|---|---|
| Rule | [`rules/windows/process_creation/proc_creation_win_schtasks_create_suspicious.yml`](../rules/windows/process_creation/proc_creation_win_schtasks_create_suspicious.yml) |
| Severity | medium |
| ATT&CK | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| Test samples | [`tests/data/proc_creation_win_schtasks_create_suspicious/`](../tests/data/proc_creation_win_schtasks_create_suspicious/) |

## What it means

A scheduled task was created that starts a script interpreter or LOLBin, runs from a
user-writable folder, decodes Base64 or runs as SYSTEM. The recordings show two uses: an
Empire agent creating a daily task that rebuilds its stager from the registry
(`powershell -c "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:...).debug)))"`),
and a remote task on `WORKSTATION6` (`/S`) running as SYSTEM at startup.

## Investigate

1. Read the full task: `schtasks /query /tn <name> /xml` or
   `C:\Windows\System32\Tasks\<name>`. Look at the action, trigger and account.
2. For a remote task (`/S`), investigate both hosts: the one that ran `schtasks` and the
   target.
3. If the action reads the registry or a file (as Empire does), collect that value: it is
   the payload.
4. Check the TaskScheduler Operational log (106, 140, 200, 201) to see whether it ran.

## False positives

- Installers and IT scripts registering maintenance tasks. They use stable names and
  vendor paths; baseline by task name and parent process.

## Respond

- Delete the task (`schtasks /delete /tn <name> /f`) after collecting its XML.
- Remove the payload it points to and hunt for the task name on other hosts.
- For remote creation, treat the source account as compromised.
