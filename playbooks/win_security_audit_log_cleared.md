# Security Event Log Cleared

| | |
|---|---|
| Rule | [`rules/windows/builtin/security/win_security_audit_log_cleared.yml`](../rules/windows/builtin/security/win_security_audit_log_cleared.yml) |
| Severity | high |
| ATT&CK | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) |
| Test samples | [`tests/data/win_security_audit_log_cleared/`](../tests/data/win_security_audit_log_cleared/) |

## What it means

The Security log was cleared. Everything recorded before that moment on this host is gone
(unless it was already forwarded to the SIEM). It is rarely legitimate in production. The
recorded samples come from the OTRF lab clearing its logs before each simulation, which is
the typical benign case: a planned reset.

## Investigate

1. Identify the account that cleared it (`SubjectUserName` in 1102) and its logon session.
2. Check the SIEM for the events from this host *before* the clear: they were forwarded
   and show what the attacker wanted to hide.
3. Look for other logs cleared at the same time (System 104) and for `wevtutil cl` or
   `Clear-EventLog` in process creation or PowerShell logs.
4. Was there a maintenance window or a reimage?

## False positives

- Planned resets of labs, golden images and test machines.
- An administrator clearing a full log while troubleshooting (should be documented).

## Respond

- If unplanned, treat the host as compromised: something worth hiding happened before.
- Make sure logs are forwarded in near real time, so that clearing them locally does not
  erase the evidence.
