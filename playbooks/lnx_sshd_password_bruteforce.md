# SSH Password Brute Force From a Single Source

| | |
|---|---|
| Rule | [`rules/linux/sshd/lnx_sshd_password_bruteforce.yml`](../rules/linux/sshd/lnx_sshd_password_bruteforce.yml) |
| Severity | medium |
| ATT&CK | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Test samples | [`tests/data/lnx_sshd_password_bruteforce/`](../tests/data/lnx_sshd_password_bruteforce/) |

## What it means

One address failed SSH password authentication at least 10 times in 5 minutes. The recorded
sample is a real Internet-facing server: `5.188.10.180` guessed passwords for `admin` (11 times),
`default`, `guest`, `ftp` and others in a few minutes. The alert says nothing about success; that is the first thing to check.

## Investigate

1. Look for an `Accepted password` or `Accepted publickey` from the same address, or
   for the targeted accounts, after the failures. A success after a burst of failures is the
   critical case.
2. Which accounts were tried? `root` and generic names suggest an untargeted bot; real
   employee names suggest a targeted attack.
3. Check the address's reputation and whether it hits other servers (group the base query
   by `src_ip` across hosts).

## False positives

- A script or monitoring probe retrying with an expired password: one internal address,
  always the same account.

## Respond

- If a login succeeded: treat the account and server as compromised, kill the session,
  rotate the credential, review `~/.ssh/authorized_keys`, crontab and new users.
- Otherwise: block the address (fail2ban, firewall), disable password authentication
  (`PasswordAuthentication no`), disallow root login, and restrict SSH by source address.
