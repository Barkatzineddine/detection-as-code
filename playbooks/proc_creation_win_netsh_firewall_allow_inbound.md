# Firewall Rule Allowing Inbound Traffic Added With netsh

| | |
|---|---|
| Rule | [`rules/windows/process_creation/proc_creation_win_netsh_firewall_allow_inbound.yml`](../rules/windows/process_creation/proc_creation_win_netsh_firewall_allow_inbound.yml) |
| Severity | medium |
| ATT&CK | [T1686.003](https://attack.mitre.org/techniques/T1686/003/) |
| Test samples | [`tests/data/proc_creation_win_netsh_firewall_allow_inbound/`](../tests/data/proc_creation_win_netsh_firewall_allow_inbound/) |

## What it means

A firewall rule allowing traffic was added from the command line. Attackers open a port for a
backdoor, RDP or remote management. The recorded test added
`netsh advfirewall firewall add rule name="atomic testing" action=allow dir=in protocol=TCP localport=450`.

## Investigate

1. Read the rule: direction, port, program, remote addresses
   (`netsh advfirewall firewall show rule name=<name>`).
2. Find what listens on that port now (Sysmon 3, `netstat -ano`).
3. Identify the user and parent. Firewall changes are normally pushed by Group Policy.

## False positives

- Installers opening their own port, and administrators. Push firewall configuration by
  Group Policy so that manual `netsh` use stands out.

## Respond

- Remove the rule and stop the listener, then look for inbound connections that used it.
- Investigate the account and process that made the change.
