# SSH Logins Tried for Many User Names From a Single Source

| | |
|---|---|
| Rule | [`rules/linux/sshd/lnx_sshd_invalid_user_enumeration.yml`](../rules/linux/sshd/lnx_sshd_invalid_user_enumeration.yml) |
| Severity | medium |
| ATT&CK | [T1110.003](https://attack.mitre.org/techniques/T1110/003/), [T1087](https://attack.mitre.org/techniques/T1087/) |
| Test samples | [`tests/data/lnx_sshd_invalid_user_enumeration/`](../tests/data/lnx_sshd_invalid_user_enumeration/) |

## What it means

One address tried at least five user names that do not exist on the server within ten minutes.
It is cycling through a list of common accounts (password spraying, account discovery). In the
recorded sample `103.99.0.122` tried `admin`, `support`, `user`, `1234`, `anonymous`, `ubnt`...
within minutes.

## Investigate

1. Did any attempt use a name that does exist? Look for `Failed password for <user>`
   (without "invalid user") from the same address: the spray found a valid account.
2. Look for a later success from this address or its network range.
3. Compare the names tried with your naming convention: matching names mean the attacker
   knows your organisation.

## False positives

- Internal vulnerability scanners. Exclude their documented addresses.

## Respond

- Block the address and consider geo or allow-list restrictions for SSH.
- Disable password authentication, which makes spraying useless.
- If a valid account was found, watch it closely (and force a password change).
