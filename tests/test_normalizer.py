from app.normalizer import normalize_line, normalize_lines


def test_parses_failed_ssh_login():
    line = "Sep 27 10:31:02 server sshd: Failed password for admin from 192.168.1.25"
    ev = normalize_line(line)
    assert ev["event_type"] == "LOGIN_FAILED"
    assert ev["username"] == "admin"
    assert ev["source_ip"] == "192.168.1.25"


def test_parses_accepted_ssh_login():
    line = "Sep 27 10:31:30 server sshd: Accepted password for admin from 192.168.1.25"
    ev = normalize_line(line)
    assert ev["event_type"] == "LOGIN_SUCCESS"
    assert ev["username"] == "admin"


def test_parses_sudo_privilege_escalation():
    line = "Sep 27 10:33:04 server sudo: admin : COMMAND=/bin/su ; USER=root"
    ev = normalize_line(line)
    assert ev["event_type"] == "PRIVILEGE_ESCALATION"
    assert ev["username"] == "admin"


def test_parses_sensitive_resource_access():
    line = "Sep 27 10:33:20 server app: admin accessed /etc/shadow from 192.168.1.25"
    ev = normalize_line(line)
    assert ev["event_type"] == "SENSITIVE_ACCESS"
    assert ev["username"] == "admin"
    assert ev["source_ip"] == "192.168.1.25"


def test_ignores_unrecognized_lines():
    assert normalize_line("this is not a log line") is None


def test_normalize_lines_skips_blank_and_unknown():
    lines = [
        "",
        "garbage line",
        "Sep 27 10:31:02 server sshd: Failed password for admin from 192.168.1.25",
    ]
    events = normalize_lines(lines)
    assert len(events) == 1
    assert events[0]["event_type"] == "LOGIN_FAILED"
