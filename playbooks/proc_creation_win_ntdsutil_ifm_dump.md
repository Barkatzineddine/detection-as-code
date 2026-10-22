# Active Directory Database Copied With ntdsutil IFM

| | |
|---|---|
| Rule | [`rules/windows/process_creation/proc_creation_win_ntdsutil_ifm_dump.yml`](../rules/windows/process_creation/proc_creation_win_ntdsutil_ifm_dump.yml) |
| Severity | high |
| ATT&CK | [T1003.003](https://attack.mitre.org/techniques/T1003/003/) |
| Test samples | [`tests/data/proc_creation_win_ntdsutil_ifm_dump/`](../tests/data/proc_creation_win_ntdsutil_ifm_dump/) |

## What it means

`ntdsutil` created an Install From Media set: a copy of `ntds.dit` and the SYSTEM hive. Those
two files contain the password hash of every domain account, including `krbtgt`. In the
recorded attack an administrator session on the DC ran
`ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds_T1003" q q`.

## Investigate

1. Check whether a domain controller promotion from media was planned (change ticket).
2. Identify who ran it and how they logged on to the DC (4624, RDP, PsExec, WinRM).
3. Find the output folder and look for its compression and transfer off the DC.
4. Volume Shadow Copy activity (VSSVC, `svchost -k swprv`) at the same time is expected and
   confirms the copy happened.

## False positives

- Promoting a domain controller with IFM. This is rare, planned, and done by the AD team.

## Respond

- Treat it as a full domain compromise until proven otherwise.
- Reset `krbtgt` twice (with replication in between), then privileged accounts, then
  service accounts.
- Secure the output folder as evidence and find out where else it was copied.
