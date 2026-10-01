from datetime import datetime, timedelta
from app.normalizer import normalize_lines
from app.pipeline import ingest_normalized_events
from app.sample_data import generate_attack_scenario
from app.models import Alert, Incident, LogEvent


def test_full_attack_scenario_creates_one_critical_incident(db):
    lines = generate_attack_scenario()
    logs, alerts, incidents = ingest_normalized_events(db, normalize_lines(lines))

    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"
    assert incidents[0].incident_type == "ACCOUNT_COMPROMISE"
    # every evidence log line should show up in the incident's timeline
    assert len(incidents[0].timeline_events) == len(logs)


def test_reingesting_identical_lines_creates_nothing_new(db):
    lines = generate_attack_scenario()
    ingest_normalized_events(db, normalize_lines(lines))

    logs2, alerts2, incidents2 = ingest_normalized_events(db, normalize_lines(lines))

    assert logs2 == []
    assert alerts2 == []
    assert incidents2 == []
    # confirm nothing was duplicated in the database either
    assert db.query(LogEvent).count() == len(lines)
    assert db.query(Incident).count() == 1


def test_two_separate_attacks_stay_separate_incidents(db):
    base = datetime.now().replace(microsecond=0, hour=10, minute=0, second=0)
    lines1 = generate_attack_scenario(base)
    lines2 = generate_attack_scenario(base + timedelta(hours=3))

    ingest_normalized_events(db, normalize_lines(lines1))
    ingest_normalized_events(db, normalize_lines(lines2))

    incidents = db.query(Incident).order_by(Incident.id).all()
    assert len(incidents) == 2
    assert incidents[0].incident_code != incidents[1].incident_code


def test_streaming_attack_extends_same_incident_not_duplicate(db):
    """Logs for one attack arriving in two separate batches (e.g. the sudo
    command showing up moments after the initial login batch was already
    ingested) should extend the same incident, not create a second one."""
    base = datetime.now().replace(microsecond=0, hour=9, minute=0, second=0)
    lines = generate_attack_scenario(base)

    # first batch: just the failed logins + successful login
    ingest_normalized_events(db, normalize_lines(lines[:13]))
    incidents_after_batch1 = db.query(Incident).all()
    assert len(incidents_after_batch1) == 1
    assert incidents_after_batch1[0].severity == "HIGH"

    # second batch: sudo + sensitive access, arriving moments later
    ingest_normalized_events(db, normalize_lines(lines[13:]))
    incidents_after_batch2 = db.query(Incident).all()

    assert len(incidents_after_batch2) == 1, "should extend, not duplicate"
    assert incidents_after_batch2[0].id == incidents_after_batch1[0].id
    assert incidents_after_batch2[0].severity == "CRITICAL"


def test_alert_occurred_at_reflects_event_time_not_insert_time(db):
    """Alerts must carry the timestamp of when the underlying event(s)
    actually happened (occurred_at), not when the row was inserted
    (created_at) - otherwise every alert from one ingest looks like it
    happened at the same instant, which breaks any time-based view (e.g.
    the dashboard's alerts-over-time chart). Note: syslog lines carry no
    year field, so the normalizer reconstructs the current year regardless
    of the generator's base_time year - this test checks month/day/hour/
    minute/second, which the generator does control, rather than the year."""
    base = datetime(2026, 6, 15, 14, 0, 0)
    lines = generate_attack_scenario(base)
    logs, alerts, _ = ingest_normalized_events(db, normalize_lines(lines))

    assert len(alerts) > 0
    logs_by_id = {l.id: l for l in logs}

    for a in alerts:
        assert a.occurred_at is not None
        # occurred_at must exactly match the earliest evidence log's own
        # timestamp - not "now" (when this test actually runs)
        evidence_times = [
            logs_by_id[i].timestamp for i in a.evidence_log_ids if i in logs_by_id
        ]
        assert a.occurred_at == min(evidence_times)
        # and it should match the generator's scripted date, confirming
        # it's not drifting to real insert time
        assert a.occurred_at.month == 6 and a.occurred_at.day == 15

    # alerts for different stages of the attack should have different
    # occurred_at times, spread across the scenario - not identical
    occurred_times = {a.occurred_at for a in alerts}
    assert len(occurred_times) > 1


def test_alert_count_matches_findings_not_duplicated(db):
    base = datetime(2026, 1, 1, 14, 0, 0)  # pinned to business hours - deterministic
    lines = generate_attack_scenario(base)
    _, alerts, _ = ingest_normalized_events(db, normalize_lines(lines))
    # brute force, success-after-failures, privilege escalation, sensitive access
    assert len(alerts) == 4
    assert db.query(Alert).count() == 4
