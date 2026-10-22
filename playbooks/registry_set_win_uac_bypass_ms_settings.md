# UAC Bypass Through the ms-settings Protocol Handler

| | |
|---|---|
| Rule | [`rules/windows/registry/registry_set/registry_set_win_uac_bypass_ms_settings.yml`](../rules/windows/registry/registry_set/registry_set_win_uac_bypass_ms_settings.yml) |
| Severity | high |
| ATT&CK | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) |
| Test samples | [`tests/data/registry_set_win_uac_bypass_ms_settings/`](../tests/data/registry_set_win_uac_bypass_ms_settings/) |

## What it means

A command was written to `ms-settings\Shell\Open\command` in the user's Classes hive.
`fodhelper.exe` auto-elevates and reads this key, so the command runs at high integrity
without a UAC prompt. In the recording the value was a PowerShell command loading an encoded
payload; `fodhelper.exe` then started it elevated and the keys were deleted.

## Investigate

1. Read the value and decode the payload.
2. Look for `fodhelper.exe` or `computerdefaults.exe` starting within seconds, and for a
   high-integrity child process.
3. Check whether the keys were deleted shortly after (Sysmon 12 DeleteKey): cleanup is part
   of the tool.
4. The user is a local administrator with UAC as the only barrier: what else ran in that
   session?

## False positives

- None expected. Windows does not register an `ms-settings` command in the user hive.

## Respond

- The attacker has high integrity on the host: isolate it and investigate as admin
  compromise.
- Set UAC to "Always notify" and remove local admin rights from daily-use accounts.
