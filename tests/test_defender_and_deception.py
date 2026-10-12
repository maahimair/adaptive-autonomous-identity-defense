# tests/test_defender_and_deception.py
# Unit coverage for the AAIDD defender and deception modules.
#
# Everything here runs offline: no SSH, no network, no log file handles held open.

import json
import os
import shutil
import sys
import threading
import time

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

for module_dir in ("defender_engine", "deception_tarpit", "threat_swarm"):
    path = os.path.join(REPO_ROOT, module_dir)
    if path not in sys.path:
        sys.path.insert(0, path)

from log_sentinel import (                                  # noqa: E402
    HEAD_FINGERPRINT_BYTES,
    LogInterceptorSentinel,
)
from mock_shell import AdaptiveDeceptionTarpit            # noqa: E402
from swarm_sync import ThreatSwarmSyncClient              # noqa: E402


AUTH_LOG_LINE = (
    "Jun 15 12:00:02 prod-db sshd[1101]: Failed password for root "
    "from 198.51.100.42 port 41234 ssh2"
)
INVALID_USER_LINE = (
    "Jun 15 12:00:03 prod-db sshd[1102]: Failed password for invalid user admin "
    "from 198.51.100.42 port 41235 ssh2"
)

#: Pre-existing, benign log content used to start the tailing tests. Long
#: enough that the head fingerprint is a complete prefix.
SETTLED_LOG = "".join(
    f"Jun 15 11:{minute:02d}:00 prod-db sshd[1]: Accepted password for deploy\n"
    for minute in range(10)
)


@pytest.fixture
def sentinel(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("", encoding="utf-8")
    return LogInterceptorSentinel(str(log_file), str(tmp_path / "alerts.json"))


@pytest.fixture
def alerts_path(tmp_path):
    return str(tmp_path / "telemetry.json")


@pytest.fixture
def tarpit(alerts_path):
    return AdaptiveDeceptionTarpit(alerts_path)


def read_alerts(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


# ─── Log parsing ──────────────────────────────────────────────────────────────

def test_parses_failed_password_line(sentinel):
    sentinel.process_log_entry(AUTH_LOG_LINE)
    assert "198.51.100.42" in sentinel.ip_state_history


def test_parses_invalid_user_variant(sentinel):
    sentinel.process_log_entry(INVALID_USER_LINE)
    assert "198.51.100.42" in sentinel.ip_state_history


def test_ignores_unrelated_lines(sentinel):
    sentinel.process_log_entry("Jun 15 12:00:00 prod-db sshd[999]: Server started.")
    sentinel.process_log_entry("")
    assert sentinel.ip_state_history == {}


def test_separates_state_per_source_ip(sentinel):
    sentinel.process_log_entry(AUTH_LOG_LINE)
    sentinel.process_log_entry(
        "Jun 15 12:00:04 prod-db sshd[3]: Failed password for root "
        "from 203.0.113.17 port 1 ssh2"
    )
    assert set(sentinel.ip_state_history) == {"198.51.100.42", "203.0.113.17"}


# ─── Threshold behaviour ──────────────────────────────────────────────────────

def test_below_threshold_does_not_alert(sentinel, tmp_path):
    sentinel.threshold_limit = 3
    sentinel.process_log_entry(AUTH_LOG_LINE)
    sentinel.process_log_entry(AUTH_LOG_LINE)
    assert read_alerts(str(tmp_path / "alerts.json")) == []


def test_threshold_breach_raises_one_alert(sentinel, tmp_path):
    sentinel.threshold_limit = 3
    for _ in range(5):
        sentinel.process_log_entry(AUTH_LOG_LINE)

    alerts = read_alerts(str(tmp_path / "alerts.json"))
    # One burst must not emit one alert per line.
    assert len(alerts) == 1
    assert alerts[0]["indicators"]["attacker_ip"] == "198.51.100.42"
    assert alerts[0]["event_id"] == "AAIDD-IDENTITY-ANOMALY-01"


def test_alert_payload_has_expected_schema(sentinel, tmp_path):
    sentinel.threshold_limit = 2
    sentinel.process_log_entry(AUTH_LOG_LINE)
    sentinel.process_log_entry(AUTH_LOG_LINE)

    alert = read_alerts(str(tmp_path / "alerts.json"))[0]
    assert set(alert) == {
        "event_id", "alert_timestamp", "source_incident_time",
        "indicators", "risk_assessment",
    }
    assert alert["risk_assessment"]["confidence_rating"] == "High"


def test_window_expiry_prevents_alert(sentinel, tmp_path):
    sentinel.threshold_limit = 3
    sentinel.window_seconds = 10.0

    # Two failures, then simulate the window having elapsed by rewinding the
    # recorded timestamps far enough back that they fall out of the window.
    sentinel.process_log_entry(AUTH_LOG_LINE)
    sentinel.process_log_entry(AUTH_LOG_LINE)
    sentinel.ip_state_history["198.51.100.42"] = [
        ts - 3600 for ts in sentinel.ip_state_history["198.51.100.42"]
    ]

    sentinel.process_log_entry(AUTH_LOG_LINE)
    assert read_alerts(str(tmp_path / "alerts.json")) == []


def test_alert_rearms_after_burst_subsides(sentinel, tmp_path):
    sentinel.threshold_limit = 2
    sentinel.window_seconds = 10.0

    sentinel.process_log_entry(AUTH_LOG_LINE)
    sentinel.process_log_entry(AUTH_LOG_LINE)
    assert len(read_alerts(str(tmp_path / "alerts.json"))) == 1

    # Age the window out, then trigger a second genuine burst.
    sentinel.ip_state_history["198.51.100.42"] = [
        ts - 3600 for ts in sentinel.ip_state_history["198.51.100.42"]
    ]
    sentinel.process_log_entry(AUTH_LOG_LINE)
    sentinel.process_log_entry(AUTH_LOG_LINE)

    assert len(read_alerts(str(tmp_path / "alerts.json"))) == 2


def test_sanitises_hostile_username(sentinel, tmp_path):
    sentinel.threshold_limit = 1
    sentinel.process_log_entry(
        "Jun 15 12:00:02 host sshd[1]: Failed password for root "
        "from 198.51.100.42 port 1 ssh2"
    )
    alert = read_alerts(str(tmp_path / "alerts.json"))[0]
    user = alert["indicators"]["targeted_identity"]
    assert set(user) <= set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")


# ─── Telemetry persistence ────────────────────────────────────────────────────

def test_alert_write_creates_missing_directory(tmp_path):
    """The output directory must be created; open(..., "a") does not do it."""
    log_file = tmp_path / "auth.log"
    log_file.write_text("", encoding="utf-8")
    nested = tmp_path / "fresh" / "nested" / "alerts.json"
    engine = LogInterceptorSentinel(str(log_file), str(nested))

    for _ in range(3):
        engine.process_log_entry(AUTH_LOG_LINE)

    assert nested.exists()
    assert len(read_alerts(str(nested))) == 1


def test_failed_alert_write_does_not_mark_source_alerted(tmp_path):
    """A persist that fails must not burn the dedup flag.

    Marking the source alerted before confirming the write made a failed
    write a permanent suppression: the alert was announced on the console,
    stored nowhere, and never retried for the life of the process.
    """
    log_file = tmp_path / "auth.log"
    log_file.write_text("", encoding="utf-8")

    # A regular file where a directory is required, so the write cannot succeed.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    engine = LogInterceptorSentinel(str(log_file), str(blocker / "alerts.json"))

    for _ in range(3):
        engine.process_log_entry(AUTH_LOG_LINE)

    assert "198.51.100.42" not in engine.alerted_ips


def test_write_to_siem_buffer_reports_success(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("", encoding="utf-8")
    target = tmp_path / "out" / "alerts.json"
    engine = LogInterceptorSentinel(str(log_file), str(target))

    assert engine.write_to_siem_buffer({"event_id": "X"}) is True

    blocker = tmp_path / "blocker2"
    blocker.write_text("not a directory", encoding="utf-8")
    broken = LogInterceptorSentinel(str(log_file), str(blocker / "alerts.json"))
    assert broken.write_to_siem_buffer({"event_id": "X"}) is False


# ─── Log rotation and truncation ──────────────────────────────────────────────

def _wait_for(predicate, timeout=6.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.mark.parametrize("regrow_delay", [0.0, 0.15])
def test_copytruncate_rotation_still_alerts(tmp_path, regrow_delay):
    """`copytruncate` keeps the inode, so the rotation branch never fires.

    Without truncation handling the read offset stays past the new end of
    file and every attack line written after a logrotate cycle goes unseen
    for the remaining lifetime of the process. Both timings are covered: a
    delay lets a size comparison catch it, no delay requires noticing that
    the bytes at offset 0 changed.
    """
    log_file = tmp_path / "auth.log"
    # A realistic starting size. The head-fingerprint signal needs more bytes
    # than HEAD_FINGERPRINT_BYTES to be a complete prefix, and a real auth.log
    # is never shorter than that.
    log_file.write_text(SETTLED_LOG, encoding="utf-8")
    alerts = tmp_path / "alerts.json"

    engine = LogInterceptorSentinel(str(log_file), str(alerts))
    worker = threading.Thread(
        target=engine.start_tail_interceptor, kwargs={"poll_interval": 0.02}, daemon=True
    )
    worker.start()
    time.sleep(0.4)

    inode_before = os.stat(log_file).st_ino

    # logrotate's copytruncate: copy the file away, then empty it in place.
    shutil.copyfile(str(log_file), str(tmp_path / "auth.log.1"))
    log_file.write_text("", encoding="utf-8")
    assert os.stat(log_file).st_ino == inode_before, "copytruncate must preserve the inode"

    time.sleep(regrow_delay)
    for i in range(3):
        with open(log_file, "a", encoding="utf-8") as handle:
            handle.write(AUTH_LOG_LINE + "\n")
        time.sleep(0.2)

    assert _wait_for(lambda: alerts.exists()), "no alert raised after copytruncate"
    alerts_written = read_alerts(str(alerts))
    assert len(alerts_written) == 1
    assert alerts_written[0]["indicators"]["attacker_ip"] == "198.51.100.42"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "Windows refuses to rename or replace a file that is open, and the "
        "tailer holds the log open by design. This covers the rename-style "
        "rotation path, which copytruncate does not exercise."
    ),
)
def test_tail_loop_follows_a_renamed_rotation(tmp_path):
    """The rename-style rotation path must keep working."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(SETTLED_LOG, encoding="utf-8")
    alerts = tmp_path / "alerts.json"

    engine = LogInterceptorSentinel(str(log_file), str(alerts))
    threading.Thread(
        target=engine.start_tail_interceptor, kwargs={"poll_interval": 0.02}, daemon=True
    ).start()
    time.sleep(0.4)

    os.rename(str(log_file), str(tmp_path / "auth.log.1"))
    log_file.write_text("Jun 15 12:00:00 host sshd[1]: fresh file\n", encoding="utf-8")

    for _ in range(3):
        with open(log_file, "a", encoding="utf-8") as handle:
            handle.write(AUTH_LOG_LINE + "\n")
        time.sleep(0.2)

    assert _wait_for(lambda: alerts.exists())
    assert len(read_alerts(str(alerts))) == 1


def test_head_fingerprint_reads_the_head_without_moving_the_read_offset(tmp_path):
    """Probing the head must not disturb the tailer's own file position."""
    log_file = tmp_path / "auth.log"
    log_file.write_text("head bytes\n", encoding="utf-8")
    engine = LogInterceptorSentinel(str(log_file), str(tmp_path / "alerts.json"))

    first = engine._head_fingerprint()
    assert first
    assert first == engine._head_fingerprint(), "fingerprint is not stable across calls"

    with open(log_file, "a", encoding="utf-8") as handle:
        handle.write("plus more\n")
    assert engine._head_fingerprint() != first, "a grown short file yields new bytes"


def test_head_fingerprint_is_complete_past_the_sample_window(tmp_path):
    """On a file larger than the sample window, an append must be
    indistinguishable from no change at all - that is what lets the tailer
    tell an in-place rewrite apart from ordinary growth.
    """
    log_file = tmp_path / "auth.log"
    filler = "Jun 15 11:00:00 host sshd[1]: Accepted password for auser\n"
    log_file.write_text(filler * 4, encoding="utf-8")
    assert len(filler) * 4 > HEAD_FINGERPRINT_BYTES

    engine = LogInterceptorSentinel(str(log_file), str(tmp_path / "alerts.json"))
    first = engine._head_fingerprint()
    assert len(first) == HEAD_FINGERPRINT_BYTES

    with open(log_file, "a", encoding="utf-8") as handle:
        handle.write(filler)
    assert engine._head_fingerprint() == first, "an append must not look like a rewrite"

    log_file.write_text("Sep 01 09:00:00 totally different content here\n", encoding="utf-8")
    assert engine._head_fingerprint() != first, "a rewrite must change the fingerprint"


# ─── Deception tarpit ─────────────────────────────────────────────────────────

def test_pwd_reports_working_directory(tarpit):
    assert tarpit.process_command("pwd") == "/home/ubuntu"


def test_cd_changes_directory(tarpit):
    assert tarpit.process_command("cd /etc") == ""
    assert tarpit.current_working_directory == "/etc"
    assert tarpit.process_command("pwd") == "/etc"


def test_cd_to_missing_directory_fails_safely(tarpit):
    assert "No such file" in tarpit.process_command("cd /nonexistent")
    assert tarpit.current_working_directory == "/home/ubuntu"


def test_cd_dotdot_cannot_escape_root(tarpit):
    tarpit.process_command("cd /../../../../etc/shadow")
    # Resolved lexically and clamped at the simulated root.
    assert tarpit.current_working_directory in tarpit.mock_file_system


def test_ls_lists_current_directory(tarpit):
    assert "db_backup.sql" in tarpit.process_command("ls")


def test_cat_passwd_returns_decoy_not_real_file(tarpit):
    output = tarpit.process_command("cat /etc/passwd")
    assert "ubuntu:x:1000" in output


def test_cat_missing_file_reports_error(tarpit):
    assert "No such file" in tarpit.process_command("cat /etc/real_secret")


def test_unknown_command_is_simulated(tarpit):
    assert tarpit.process_command("definitelynotacommand") == \
        "definitelynotacommand: command not found"


def test_rm_pretends_to_succeed_without_touching_disk(tarpit, tmp_path):
    marker = tmp_path / "precious.txt"
    marker.write_text("intact", encoding="utf-8")
    tarpit.process_command("rm /precious.txt")
    assert marker.exists()


def test_sudo_does_not_escalate(tarpit):
    assert "incorrect password" in tarpit.process_command("sudo -l")


def test_empty_command_returns_nothing(tarpit):
    assert tarpit.process_command("   ") == ""


def test_every_command_is_logged(tarpit, alerts_path):
    for command in ("ls -la", "cat /etc/passwd", "env"):
        tarpit.log_attacker_action(command)

    alerts = read_alerts(alerts_path)
    assert len(alerts) == 3
    assert [a["captured_input"] for a in alerts] == \
        ["ls -la", "cat /etc/passwd", "env"]
    assert alerts[0]["environment_state"]["session_status"] == "Trapped"


def test_telemetry_creates_missing_directory(tarpit, tmp_path):
    nested = str(tmp_path / "deep" / "nested" / "telemetry.json")
    session = AdaptiveDeceptionTarpit(nested)
    session.log_attacker_action("whoami")
    assert len(read_alerts(nested)) == 1


def test_telemetry_loss_does_not_crash(tarpit):
    # An unwritable path must not hand back a real shell.
    tarpit.output_telemetry_path = "\x00invalid/path.json"
    tarpit.log_attacker_action("whoami")   # must not raise
    assert tarpit.process_command("pwd") == "/home/ubuntu"


# ─── Swarm sync ───────────────────────────────────────────────────────────────

def test_client_refuses_empty_secret():
    with pytest.raises(ValueError):
        ThreatSwarmSyncClient("node", "", "https://registry.invalid")


def test_signature_is_deterministic():
    a = ThreatSwarmSyncClient("node", "s3cret", "https://registry.invalid")
    b = ThreatSwarmSyncClient("node", "s3cret", "https://registry.invalid")
    assert a.generate_secure_signature("payload") == \
        b.generate_secure_signature("payload")


def test_signature_differs_per_secret():
    a = ThreatSwarmSyncClient("node", "s3cret", "https://registry.invalid")
    b = ThreatSwarmSyncClient("node", "other", "https://registry.invalid")
    assert a.generate_secure_signature("payload") != \
        b.generate_secure_signature("payload")


def test_packet_contains_signature_and_payload():
    client = ThreatSwarmSyncClient("node", "s3cret", "https://registry.invalid")
    packet = client.build_packet("198.51.100.42", "Distributed Auth Flood")
    assert set(packet) == {"secure_signature", "payload"}
    assert packet["payload"]["origin_node"] == "node"
    assert packet["payload"]["threat_actor_ip"] == "198.51.100.42"


def test_verify_signature_accepts_own_packet():
    client = ThreatSwarmSyncClient("node", "s3cret", "https://registry.invalid")
    packet = client.build_packet("198.51.100.42", "Distributed Auth Flood")
    serialized = json.dumps(packet["payload"], sort_keys=True)
    assert client.verify_signature(serialized, packet["secure_signature"])


def test_verify_signature_rejects_forged_packet():
    client = ThreatSwarmSyncClient("node", "s3cret", "https://registry.invalid")
    packet = client.build_packet("198.51.100.42", "Distributed Auth Flood")
    packet["payload"]["threat_actor_ip"] = "10.0.0.1"   # tampered after signing
    serialized = json.dumps(packet["payload"], sort_keys=True)
    assert not client.verify_signature(serialized, packet["secure_signature"])


def test_broadcast_rejects_empty_indicator():
    client = ThreatSwarmSyncClient("node", "s3cret", "https://registry.invalid")
    assert client.broadcast_malicious_indicator("", "anything", dry_run=True) is False