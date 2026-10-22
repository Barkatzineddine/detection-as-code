"""Decode OpenSSH syslog lines into flat events.

This is the job a SIEM decoder does (Wazuh's ``sshd`` decoder, Filebeat's ``system/auth``
module): one RFC 3164 line becomes one event with named fields. The Linux rules match on
these field names; ``pipelines/`` maps them to Wazuh and ECS names for conversion.

Fields: ``timestamp`` (ISO 8601), ``host``, ``process``, ``pid``, ``message`` and, when the
message carries them, ``user``, ``src_ip`` and ``src_port``.
"""

from __future__ import annotations

import re
from datetime import datetime

_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) "
    r"(?P<process>[\w./-]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)

# Order matters: the first pattern that matches the message wins.
_MESSAGE_PATTERNS = [
    re.compile(
        r"^Failed (?:password|none|publickey) for (?:invalid user )?(?P<user>\S*) "
        r"from (?P<src_ip>\S+) port (?P<src_port>\d+)"
    ),
    re.compile(r"^Accepted \S+ for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"),
    re.compile(r"^Invalid user (?P<user>.*?) from (?P<src_ip>\S+?)(?: port (?P<src_port>\d+))?$"),
    re.compile(
        r"^pam_unix\(sshd:auth\): authentication failure;.*rhost=(?P<src_ip>\S+)"
        r"(?:\s+user=(?P<user>\S+))?"
    ),
    re.compile(r"^(?:error: )?Received disconnect from (?P<src_ip>[0-9a-fA-F.:]+?)(?: port \d+)?:"),
    re.compile(r"^Connection closed by (?P<src_ip>\S+?)(?: port \d+)?(?: \[preauth\])?$"),
    re.compile(r"^Did not receive identification string from (?P<src_ip>\S+)"),
    re.compile(r"^reverse mapping checking getaddrinfo for \S+ \[(?P<src_ip>[^\]]+)\]"),
]


def parse_line(line: str, year: int) -> dict | None:
    """Return the event for one syslog line, or None when the line is not syslog.

    RFC 3164 timestamps carry no year, so the caller supplies it.
    """
    match = _SYSLOG.match(line.rstrip("\r\n"))
    if not match:
        return None
    stamp = datetime.strptime(f"{year} {match['ts']}", "%Y %b %d %H:%M:%S")
    event = {
        "timestamp": stamp.isoformat(),
        "host": match["host"],
        "process": match["process"],
        "message": match["message"],
    }
    if match["pid"]:
        event["pid"] = int(match["pid"])
    for pattern in _MESSAGE_PATTERNS:
        found = pattern.match(match["message"])
        if found:
            event.update({k: v for k, v in found.groupdict().items() if v is not None})
            break
    return event


def parse_lines(lines, year: int) -> list[dict]:
    return [event for line in lines if (event := parse_line(line, year))]
