# LSASS Dump via comsvcs.dll MiniDump

| | |
|---|---|
| Rule | [`rules/windows/process_creation/proc_creation_win_rundll32_comsvcs_minidump.yml`](../rules/windows/process_creation/proc_creation_win_rundll32_comsvcs_minidump.yml) |
| Severity | critical |
| ATT&CK | [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1218.011](https://attack.mitre.org/techniques/T1218/011/) |
| Test samples | [`tests/data/proc_creation_win_rundll32_comsvcs_minidump/`](../tests/data/proc_creation_win_rundll32_comsvcs_minidump/) |

## What it means

`rundll32.exe` called the `MiniDump` export of `comsvcs.dll`, a Windows DLL that can write a
full memory dump of any process. The usual target is LSASS. The recorded attack ran
`rundll32.exe C:\windows\System32\comsvcs.dll MiniDump 756 ...\lsass-comsvcs.dmp full`,
where 756 was the PID of LSASS.

## Investigate

1. Check which PID was dumped and confirm it was `lsass.exe` at that time.
2. Find the dump file (path in the command line) and when it was created, copied,
   compressed or deleted (Sysmon 11, 23, 26).
3. Identify the parent and the user: an interactive admin, a remote shell
   (`wmiprvse.exe`, `services.exe`), or a script.
4. Look for outbound transfers of the file: SMB, HTTP uploads, cloud storage clients.

## False positives

- None expected. Legitimate dumps are created by `WerFault.exe`, ProcDump or a debugger.

## Respond

- Contain the host. Consider all credentials cached in LSASS stolen and reset them.
- Delete the dump only after it has been collected as evidence.
- Hunt for the same command line across the fleet: this is often scripted.
