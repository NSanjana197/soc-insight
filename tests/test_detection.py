from datetime import datetime, timedelta
from app.models import LogEvent
from app.detection import (
    detect_brute_force,
    detect_success_after_failures,
    detect_unusual_login_time,
    detect_privilege_escalation,
    detect_sensitive_access,
    detect_new_source_ip,
    run_all_detectors,
)


def make_event(db, i, minutes_offset, username, ip, event_type, service="SSH"):
    ev = LogEvent(
        timestamp=datetime(2026, 1, 1, 12, 0, 0) + timedelta(minutes=minutes_offset),
        username=username,
        source_ip=ip,
        event_type=event_type,
        service=service,
        raw_log=f"synthetic-{i}",
    )
    db.add(ev)
    db.flush()
    return ev


def test_brute_force_triggers_at_threshold(db):
    events = [
        make_event(db, i, i * 0.1, "admin", "1.2.3.4", "LOGIN_FAILED")
        for i in range(10)
    ]
    findings = detect_brute_force(events)
    assert len(findings) == 1
    assert findings[0]["alert_type"] == "BRUTE_FORCE"
    assert findings[0]["severity"] == "HIGH"


def test_brute_force_does_not_trigger_below_threshold(db):
    events = [
        make_event(db, i, i * 0.1, "admin", "1.2.3.4", "LOGIN_FAILED")
        for i in range(9)
    ]
    assert detect_brute_force(events) == []


def test_success_after_failures(db):
    events = [
        make_event(db, i, i, "admin", "1.2.3.4", "LOGIN_FAILED") for i in range(4)
    ]
    events.append(make_event(db, 99, 4, "admin", "1.2.3.4", "LOGIN_SUCCESS"))
    findings = detect_success_after_failures(events)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_unusual_login_time_flags_3am():
    ev = LogEvent(
        timestamp=datetime(2026, 1, 1, 3, 15, 0),
        username="bob", source_ip="1.2.3.4",
        event_type="LOGIN_SUCCESS", service="SSH", id=1,
    )
    findings = detect_unusual_login_time([ev])
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_unusual_login_time_ignores_business_hours():
    ev = LogEvent(
        timestamp=datetime(2026, 1, 1, 14, 0, 0),
        username="bob", source_ip="1.2.3.4",
        event_type="LOGIN_SUCCESS", service="SSH", id=1,
    )
    assert detect_unusual_login_time([ev]) == []


def test_privilege_escalation_requires_recent_login(db):
    login = make_event(db, 1, 0, "admin", "1.2.3.4", "LOGIN_SUCCESS")
    sudo = make_event(db, 2, 5, "admin", None, "PRIVILEGE_ESCALATION")
    findings = detect_privilege_escalation([login, sudo])
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_privilege_escalation_ignored_without_recent_login(db):
    sudo = make_event(db, 1, 100, "admin", None, "PRIVILEGE_ESCALATION")
    assert detect_privilege_escalation([sudo]) == []


def test_sensitive_access_after_escalation_is_critical(db):
    esc = make_event(db, 1, 0, "admin", None, "PRIVILEGE_ESCALATION")
    access = make_event(db, 2, 5, "admin", "1.2.3.4", "SENSITIVE_ACCESS")
    findings = detect_sensitive_access([esc, access])
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_new_source_ip_is_low_severity(db):
    first = make_event(db, 1, 0, "lrossi", "10.0.0.1", "LOGIN_SUCCESS")
    second = make_event(db, 2, 60, "lrossi", "10.0.0.2", "LOGIN_SUCCESS")
    findings = detect_new_source_ip([first, second])
    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"


def test_new_source_ip_does_not_fire_on_first_login(db):
    first = make_event(db, 1, 0, "lrossi", "10.0.0.1", "LOGIN_SUCCESS")
    assert detect_new_source_ip([first]) == []


def test_full_attack_chain_detected_together(db):
    events = [
        make_event(db, i, i * 0.3, "admin", "1.2.3.4", "LOGIN_FAILED")
        for i in range(12)
    ]
    events.append(make_event(db, 20, 4, "admin", "1.2.3.4", "LOGIN_SUCCESS"))
    events.append(make_event(db, 21, 6, "admin", None, "PRIVILEGE_ESCALATION"))
    events.append(make_event(db, 22, 8, "admin", "1.2.3.4", "SENSITIVE_ACCESS"))

    findings = run_all_detectors(db, events)
    alert_types = {f["alert_type"] for f in findings}
    assert "BRUTE_FORCE" in alert_types
    assert "SUCCESS_AFTER_FAILURES" in alert_types
    assert "PRIVILEGE_ESCALATION" in alert_types
    assert "SENSITIVE_RESOURCE_ACCESS" in alert_types
