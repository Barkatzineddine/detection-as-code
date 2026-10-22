# Audit Policy Disabled or Cleared With auditpol

| | |
|---|---|
| Rule | [`rules/windows/process_creation/proc_creation_win_auditpol_disable_logging.yml`](../rules/windows/process_creation/proc_creation_win_auditpol_disable_logging.yml) |
| Severity | high |
| ATT&CK | [T1685.001](https://attack.mitre.org/techniques/T1685/001/) |
| Test samples | [`tests/data/proc_creation_win_auditpol_disable_logging/`](../tests/data/proc_creation_win_auditpol_disable_logging/) |

## What it means

The audit policy was weakened from the command line: auditing disabled for a category,
per-user policy removed, or the whole policy cleared. Security events stop being generated,
so what follows is invisible. The recording shows a `payload.exe` running six auditpol
commands in 90 seconds, from `/set /user:pedro /category:"DS Access" /success:disable` to
`/clear /y`.

## Investigate

1. List the commands run and the categories affected; check the current policy with
   `auditpol /get /category:*`.
2. Event 4719 (system audit policy changed) confirms each change.
3. Identify the parent (here an unknown `payload.exe` in Downloads) and investigate it.
4. Look at what happened right after, in Sysmon data, which auditpol does not affect.

## False positives

- Audit policy should come from Group Policy. Local changes by an administrator during
  troubleshooting are possible but rare.

## Respond

- Restore the policy (`gpupdate /force` re-applies Group Policy) and treat the host as
  compromised.
- Alert when a host's event volume drops suddenly.
