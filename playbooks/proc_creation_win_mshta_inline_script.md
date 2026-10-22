# Mshta Executing Inline Script or a Remote HTA

| | |
|---|---|
| Rule | [`rules/windows/process_creation/proc_creation_win_mshta_inline_script.yml`](../rules/windows/process_creation/proc_creation_win_mshta_inline_script.yml) |
| Severity | high |
| ATT&CK | [T1218.005](https://attack.mitre.org/techniques/T1218/005/) |
| Test samples | [`tests/data/proc_creation_win_mshta_inline_script/`](../tests/data/proc_creation_win_mshta_inline_script/) |

## What it means

`mshta.exe` ran VBScript or JavaScript given on its command line, or an HTA from a URL. mshta
is a signed Windows binary, so it is often allowed where unknown executables are not. In the
recorded attack, `mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell ..."":close")`
started PowerShell.

## Investigate

1. Read the inline script or download the HTA in a sandbox.
2. Check the parent: Office, a browser, an email client or `explorer.exe` after opening an
   attachment points to phishing.
3. Follow the children (`powershell.exe`, `cmd.exe`) and their network activity.

## False positives

- Legacy intranet HTML applications loaded from a URL. List them by URL.

## Respond

- Isolate the host if the script launched a payload; block the URL or domain.
- Find the delivery vector (email, download) and the other recipients.
- Consider blocking `mshta.exe` with WDAC or AppLocker where it is not needed.
