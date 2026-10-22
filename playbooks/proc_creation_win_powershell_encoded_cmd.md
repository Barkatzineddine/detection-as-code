# PowerShell Started With an Encoded Command

| | |
|---|---|
| Rule | [`rules/windows/process_creation/proc_creation_win_powershell_encoded_cmd.yml`](../rules/windows/process_creation/proc_creation_win_powershell_encoded_cmd.yml) |
| Severity | high |
| ATT&CK | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1027.010](https://attack.mitre.org/techniques/T1027/010/) |
| Test samples | [`tests/data/proc_creation_win_powershell_encoded_cmd/`](../tests/data/proc_creation_win_powershell_encoded_cmd/) |

## What it means

PowerShell received its script as Base64 instead of plain text. Administrators almost never
need this; loaders use it so that the command line shows nothing readable. In the recorded
attack, `wscript.exe` running `launcher.vbs` started `powershell -noP -sta -w 1 -enc SQBm...`,
the default Empire stager.

## Investigate

1. Decode the payload: `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<blob>'))`
   (UTF-16LE). Read it in a sandbox or a text editor, never by piping it back to PowerShell.
2. Look at the parent. Office applications, `wscript`/`cscript`, `mshta`, `wmiprvse.exe`
   (WMI), `services.exe` (a new service) or a browser are strong signs of compromise.
3. Pull the PowerShell Operational log (event 4104, script block logging) for the same
   host and time: it contains the decoded script, including later stages.
4. Check what the process did next: network connections (Sysmon 3), DNS queries (22),
   files written (11) and child processes.
5. Search for the same command line on other hosts: a stager reused across hosts means
   lateral movement or a phishing wave.

## False positives

- Software deployment and RMM tools (SCCM, Intune remediation, some backup agents). They run
  from a known parent, are signed, and repeat the same blob on many hosts.
- Admin scripts that wrap complex quoting with `-EncodedCommand`. Ask the owner, then filter
  on the parent process and host group, not on the encoded content.

## Respond

- If the decoded script downloads or injects code: isolate the host, kill the process
  tree, and collect memory before rebooting.
- Block the C2 address found in the script at the proxy and firewall, and hunt for it.
- Reset the credentials of the logged-on user, and look for persistence (Run keys,
  scheduled tasks, services, WMI subscriptions: the other rules in this repository).
