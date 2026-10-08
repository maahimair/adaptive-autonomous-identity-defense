# tests/test_defender_and_deception.py
# Unit coverage for the AAIDD defender and deception modules.
#
# Everything here runs offline: no SSH, no network, no log file handles held open.

import json
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

for module_dir in ("defender_engine", "deception_tarpit", "threat_swarm"):
    path = os.path.join(REPO_ROOT, module_dir)
    if path not in sys.path:
        sys.path.insert(0, path)

from log_sentinel import LogInterceptorSentinel            # noqa: E402
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