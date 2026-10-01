"""
Generates simulated log lines matching the example attack scenario in the
project proposal (brute force -> successful login -> sudo -> sensitive
access), plus some harmless background noise. Used by the /simulate
endpoint and by tests, so you can see the whole pipeline work end-to-end
without needing a real log source connected yet.
"""

from datetime import datetime, timedelta


def generate_attack_scenario(base_time: datetime = None) -> list[str]:
    if base_time is None:
        base_time = datetime.now().replace(microsecond=0)

    lines = []
    t = base_time

    # Step 1: brute force - 12 failed attempts, same user/ip, a few seconds apart
    for _ in range(12):
        lines.append(
            f"{t.strftime('%b %d %H:%M:%S')} server sshd: "
            f"Failed password for admin from 192.168.1.25"
        )
        t += timedelta(seconds=8)

    # Step 2: one successful login
    lines.append(
        f"{t.strftime('%b %d %H:%M:%S')} server sshd: "
        f"Accepted password for admin from 192.168.1.25"
    )
    t += timedelta(seconds=90)

    # Step 3: privilege escalation
    lines.append(
        f"{t.strftime('%b %d %H:%M:%S')} server sudo: "
        f"admin : COMMAND=/bin/su ; USER=root"
    )
    t += timedelta(seconds=20)

    # Step 4: sensitive resource access
    lines.append(
        f"{t.strftime('%b %d %H:%M:%S')} server app: "
        f"admin accessed /etc/shadow from 192.168.1.25"
    )

    return lines


def generate_background_noise(base_time: datetime = None, count: int = 5) -> list[str]:
    """A handful of normal, low-signal logins from other users, so the
    dashboard/demo doesn't look completely empty of 'everyday' traffic."""
    if base_time is None:
        base_time = datetime.now().replace(microsecond=0)

    users = ["jsmith", "priya", "dnguyen", "okafor", "lrossi"]
    ips = ["10.0.0.14", "10.0.0.22", "10.0.0.31", "10.0.0.9", "10.0.0.44"]
    lines = []
    t = base_time - timedelta(hours=2)
    for i in range(count):
        lines.append(
            f"{t.strftime('%b %d %H:%M:%S')} server sshd: "
            f"Accepted password for {users[i % len(users)]} from {ips[i % len(ips)]}"
        )
        t += timedelta(minutes=7)
    return lines
