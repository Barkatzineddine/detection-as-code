# Windows Event Log Service Disabled in the Registry

| | |
|---|---|
| Rule | [`rules/windows/registry/registry_set/registry_set_win_eventlog_service_disabled.yml`](../rules/windows/registry/registry_set/registry_set_win_eventlog_service_disabled.yml) |
| Severity | high |
| ATT&CK | [T1685.001](https://attack.mitre.org/techniques/T1685/001/) |
| Test samples | [`tests/data/registry_set_win_eventlog_service_disabled/`](../tests/data/registry_set_win_eventlog_service_disabled/) |

## What it means

The EventLog service was set to "disabled". Nothing changes until the next reboot; then no
Windows event is written at all, and the SIEM stops receiving data from the host. The
recorded attack ran
`REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog /t REG_DWORD /v Start /d 4`.

## Investigate

1. Identify the process and user that changed the value.
2. Check whether the host rebooted afterwards and whether it went silent in the SIEM.
3. Look for other anti-forensic actions: audit policy changes, log clearing, security
   tools stopped.

## False positives

- None expected on managed systems.

## Respond

- Restore the value (`Start` = 2, automatic) and restart the service.
- Treat the host as compromised and look at what happened just before.
- Alert on hosts that stop sending events: a silent host is also a signal.
