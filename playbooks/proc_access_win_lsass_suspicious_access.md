# Suspicious Process Access to LSASS Memory

| | |
|---|---|
| Rule | [`rules/windows/process_access/proc_access_win_lsass_suspicious_access.yml`](../rules/windows/process_access/proc_access_win_lsass_suspicious_access.yml) |
| Severity | high |
| ATT&CK | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| Test samples | [`tests/data/proc_access_win_lsass_suspicious_access/`](../tests/data/proc_access_win_lsass_suspicious_access/) |

## What it means

A process opened LSASS with rights that allow reading its memory, or from code that is not
backed by a module on disk. LSASS holds the credentials of every user logged on since boot.
In the recorded attack, `powershell.exe` running Invoke-Mimikatz opened LSASS with
`0x1010` (`PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`), and the call trace ends
in an `UNKNOWN(...)` frame: reflectively loaded code.

## Investigate

1. Identify the source process: path, signer, parent, command line and user (Sysmon 1 for
   its ProcessGuid).
2. Decode `GrantedAccess`: `0x10` is VM_READ; `0x1fffff` is full access. Note which bits
   go beyond what the tool would legitimately need.
3. Read `CallTrace`: frames in `dbghelp.dll`/`dbgcore.dll` (MiniDumpWriteDump) mean a
   dump; `UNKNOWN` frames mean injected or reflectively loaded code.
4. Look for a dump file written right after (Sysmon 11, `.dmp` files) and for its
   exfiltration (Sysmon 3, SMB to another host).
5. List the accounts with sessions on the host at that time (4624): they are the
   credentials to consider stolen.

## False positives

- EDR, antivirus and backup agents. Filter them by full path *and* verify the signature;
  attackers name their tool after a security product.
- `WerFault.exe` when LSASS itself crashes.

## Respond

- Treat every credential cached on the host as compromised: reset passwords, and for
  privileged accounts also invalidate Kerberos tickets (reset twice for krbtgt if a DC).
- Isolate the host and capture memory before anything else.
- Enable LSA protection (RunAsPPL) and Credential Guard to make this technique harder.
