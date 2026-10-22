# Service Installed With a Shell or Script Command as Its Binary

| | |
|---|---|
| Rule | [`rules/windows/builtin/security/win_security_service_install_suspicious.yml`](../rules/windows/builtin/security/win_security_service_install_suspicious.yml) |
| Severity | high |
| ATT&CK | [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1569.002](https://attack.mitre.org/techniques/T1569/002/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/) |
| Test samples | [`tests/data/win_security_service_install_suspicious/`](../tests/data/win_security_service_install_suspicious/) |

## What it means

A service was installed whose "binary" is a command line: `%COMSPEC% /C ... powershell -enc`.
Real services point to an executable. This is how PsExec-style tools run code as SYSTEM:
they create a service on the target over SMB and start it. Both recordings (Empire
`psexec` and `smbexec`) show exactly this on `WORKSTATION6`.

## Investigate

1. Read the full `ServiceFileName` and decode any encoded PowerShell.
2. Find the source: the network logon (4624 type 3) just before, and the SMB/RPC
   connection (Sysmon 3 to port 445/135) from another host.
3. Random service names (`PGUJLOAKFQFVOMHGFQPX`) or generic ones (`Updater`) are typical
   of tooling.
4. The System log (7045) and service start (7036) show whether it ran; Sysmon 1 shows the
   child of `services.exe`.

## False positives

- Some installers create services from `%TEMP%` during setup. They match a software
  deployment window and a known installing account.

## Respond

- Isolate the target, delete the service (`sc delete`), and investigate the source host,
  where the attacker already had admin credentials.
- Reset the account used for the remote logon.
- Restrict admin share access and remote service creation to admin workstations.
