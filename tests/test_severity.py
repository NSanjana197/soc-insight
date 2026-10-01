from app.severity import classify_incident_type_and_severity


def test_sensitive_access_with_escalation_is_critical():
    t, s = classify_incident_type_and_severity(
        ["SENSITIVE_RESOURCE_ACCESS", "PRIVILEGE_ESCALATION"]
    )
    assert s == "CRITICAL"
    assert t == "ACCOUNT_COMPROMISE"


def test_brute_force_alone_is_high():
    t, s = classify_incident_type_and_severity(["BRUTE_FORCE"])
    assert s == "HIGH"


def test_unusual_time_alone_is_medium():
    t, s = classify_incident_type_and_severity(["UNUSUAL_LOGIN_TIME"])
    assert s == "MEDIUM"


def test_new_source_ip_alone_is_low():
    t, s = classify_incident_type_and_severity(["NEW_SOURCE_IP"])
    assert s == "LOW"


def test_full_chain_is_critical():
    t, s = classify_incident_type_and_severity([
        "BRUTE_FORCE", "SUCCESS_AFTER_FAILURES",
        "PRIVILEGE_ESCALATION", "SENSITIVE_RESOURCE_ACCESS",
    ])
    assert s == "CRITICAL"
    assert t == "ACCOUNT_COMPROMISE"
