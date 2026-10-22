# File Transfer Started With bitsadmin

| | |
|---|---|
| Rule | [`rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml`](../rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml) |
| Severity | medium |
| ATT&CK | [T1197](https://attack.mitre.org/techniques/T1197/), [T1105](https://attack.mitre.org/techniques/T1105/) |
| Test samples | [`tests/data/proc_creation_win_bitsadmin_download/`](../tests/data/proc_creation_win_bitsadmin_download/) |

## What it means

`bitsadmin` started a file transfer. BITS downloads in the background with retries, through
the proxy, and can run a command when the job finishes. The recorded test downloaded a file
from GitHub to `%TEMP%\bitsadmin1_flag.ps1`.

## Investigate

1. Read the URL and destination path; download the file in a sandbox.
2. List BITS jobs (`bitsadmin /list /allusers /verbose`) and the BITS-Client Operational
   log (59, 60) for other jobs, including those with a notify command.
3. Check what ran the downloaded file afterwards.

## False positives

- Old deployment scripts that still use bitsadmin. Identify them by script and URL.

## Respond

- Delete the downloaded file and cancel remaining jobs (`bitsadmin /reset /allusers`).
- Block the URL/domain and look for other hosts that contacted it.
