# Test samples

Every file here is extracted from a public dataset of recorded activity by
[`tools/build_samples.py`](../../tools/build_samples.py), following
[`sources.yml`](sources.yml). Nothing is written by hand, and CI rebuilds the samples from
the pinned datasets on every push to prove it (job *Sample provenance*).

| Folder | Content |
|---|---|
| `<rule>/attack.json` | Windows events of the recorded attack the rule must detect. Every event must match. |
| `<rule>/benign.json` | Real events of the same kind that the rule must not match: system activity, admin tools, near misses. |
| `<rule>/attack.log`, `benign.log` | Raw OpenSSH syslog lines for the Linux rules, decoded at test time by [`dac/sshd.py`](../../dac/sshd.py). |
| `_baseline/benign.json` | Background activity of the lab hosts (services, Azure guest agent, indexing, monitoring agents). |

Each rule is tested against **every** `benign` file, not only its own.

## Sources

- **Windows**: [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (MIT), at
  commit `d9d40ef`. Lab domains `theshire.local` and `pandalab`, recorded with Sysmon and
  Windows auditing while Empire, Covenant or Atomic Red Team ran each technique.
- **Linux**: [loghub `OpenSSH_2k.log`](https://github.com/logpai/loghub) (free for research
  use, notice in [`NOTICE`](../../NOTICE)): 2,000 lines from a real Internet-facing SSH
  server, with genuine brute-force traffic.

## Edits made to recorded events

Two, both applied by the build script and nowhere else:

1. **Collector metadata removed.** NXLog adds fields such as the rendered `Message`,
   `EventReceivedTime` or `SourceModuleName`. They are not part of the Windows event and no
   rule uses them.
2. **Encoded payloads truncated.** Base64 blobs longer than 100 characters (the Empire
   stagers) are cut to 48 characters followed by `[...truncated]`. The rules detect how a
   payload is launched, never its content, and a complete stager makes antivirus quarantine
   the repository on clone. Microsoft Defender did exactly that to the raw datasets while
   this project was built.

Syslog lines carry no year; `sources.yml` sets one (`syslog_year`) so that timestamps,
and therefore correlation windows, are deterministic.
