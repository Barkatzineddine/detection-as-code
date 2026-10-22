# Directory Replication Requested by a Non-Machine Account (DCSync)

| | |
|---|---|
| Rule | [`rules/windows/builtin/security/win_security_dcsync_replication_request.yml`](../rules/windows/builtin/security/win_security_dcsync_replication_request.yml) |
| Severity | high |
| ATT&CK | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| Test samples | [`tests/data/win_security_dcsync_replication_request/`](../tests/data/win_security_dcsync_replication_request/) |

## What it means

An account that is not a domain controller asked a DC to replicate secrets, using the
"Replicating Directory Changes" rights. This is DCSync: Mimikatz `lsadump::dcsync` or
Impacket `secretsdump` pulling password hashes over the network, with no code running on the
DC. In the recorded attack the user `pgustavo` performed the requests against `MORDORDC`.

## Investigate

1. Identify the account and the source host: correlate `SubjectLogonId` with the 4624
   logon on the DC to get the source IP.
2. Check why that account holds replication rights. Look for recent changes to the domain
   object's ACL (event 5136) that granted them.
3. On the source host, look for the tool: Mimikatz, Impacket (Python), or a C2 agent.
4. Check for use of the extracted hashes afterwards: logons by `krbtgt`-forged tickets
   (4769 anomalies), pass-the-hash.

## False positives

- Entra Connect (Azure AD Connect) sync accounts, filtered by name (`MSOL_`, `AAD_`).
- Identity auditing tools that read hashes to find weak passwords. They should be
  inventoried and run from a known host.

## Respond

- Domain compromise: reset `krbtgt` twice, then privileged and service accounts.
- Remove the replication rights from the account and audit who else has them.
- Isolate the source host and investigate how the account was obtained.
