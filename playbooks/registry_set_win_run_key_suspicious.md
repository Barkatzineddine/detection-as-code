# Run Key Value Launching a Script Interpreter or Payload

| | |
|---|---|
| Rule | [`rules/windows/registry/registry_set/registry_set_win_run_key_suspicious.yml`](../rules/windows/registry/registry_set/registry_set_win_run_key_suspicious.yml) |
| Severity | medium |
| ATT&CK | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| Test samples | [`tests/data/registry_set_win_run_key_suspicious/`](../tests/data/registry_set_win_run_key_suspicious/) |

## What it means

A program was registered to start at logon through a Run or RunOnce key, and the command
starts PowerShell, a script host or a LOLBin, or runs from a temporary folder. In the
recorded attack, an Empire agent wrote `HKCU\...\CurrentVersion\Run\Updater` with a PowerShell
command that reads an encoded stager from another registry value and runs it.

## Investigate

1. Read the value's full command and decode any Base64 it contains.
2. Identify the process that wrote it (`Image`) and its parent: an installer or a
   script interpreter?
3. If the command reads another registry value or file, collect it: it holds the payload.
4. Check whether it already ran: process creations after the next logon with that command
   line.

## False positives

- Vendor updaters that register a PowerShell or cmd wrapper. Review the command once and
  filter on value name, command and writing process together.

## Respond

- Export, then delete the value, and the payload it references.
- Look for other persistence created by the same process (tasks, services, WMI).
- Reset the user's credentials if the payload is a C2 agent.
