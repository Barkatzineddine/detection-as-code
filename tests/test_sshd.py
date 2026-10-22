from dac.sshd import parse_line


def test_failed_password_for_invalid_user():
    event = parse_line(
        "Dec 10 07:07:38 LabSZ sshd[24206]: Failed password for invalid user test9 "
        "from 52.80.34.196 port 36060 ssh2",
        year=2017,
    )
    assert event == {
        "timestamp": "2017-12-10T07:07:38",
        "host": "LabSZ",
        "process": "sshd",
        "pid": 24206,
        "message": "Failed password for invalid user test9 from 52.80.34.196 port 36060 ssh2",
        "user": "test9",
        "src_ip": "52.80.34.196",
        "src_port": "36060",
    }


def test_invalid_user_and_pam_failure():
    invalid = parse_line(
        "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186", 2017
    )
    assert (invalid["user"], invalid["src_ip"]) == ("webmaster", "173.234.31.186")
    pam = parse_line(
        "Dec 10 06:55:48 LabSZ sshd[24200]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=173.234.31.186  user=root",
        2017,
    )
    assert (pam["src_ip"], pam["user"]) == ("173.234.31.186", "root")


def test_single_digit_day_and_non_syslog_line():
    event = parse_line(
        "Jan  2 03:04:05 host sshd[1]: Connection closed by 10.0.0.1 port 22 [preauth]", 2018
    )
    assert event["timestamp"] == "2018-01-02T03:04:05"
    assert event["src_ip"] == "10.0.0.1"
    assert parse_line("not a syslog line", 2018) is None
