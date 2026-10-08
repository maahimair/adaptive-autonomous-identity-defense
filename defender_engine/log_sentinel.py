import os
import re
import sys
import json
import time
from typing import Dict, Any

class LogInterceptorSentinel:
    def __init__(self, target_log_path: str, output_json_path: str,
                 threshold_limit: int = 3, window_seconds: float = 10.0):
        self.target_log_path = self.verify_safe_path(target_log_path)
        self.output_json_path = output_json_path

        # Matches standard Linux auth.log structural formats safely
        self.log_regex = re.compile(
            r"(?P<timestamp>\b[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\b).*?"
            r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip_address>\S+)"
        )

        # State tracker to record behavioral timestamps per IP
        self.ip_state_history: Dict[str, list] = {}
        self.threshold_limit = threshold_limit  # Maximum failures permitted
        self.window_seconds = window_seconds    # Time horizon for tracking

        # IPs already alerted on, so one burst raises one alert rather than one
        # per subsequent line inside the same window.
        self.alerted_ips: set = set()

    def verify_safe_path(self, path: str) -> str:
        """Verifies target path structural safety constraints before opening file system descriptors."""
        normalized_path = os.path.abspath(path)
        # Enforce file existence validation check
        if not os.path.exists(normalized_path):
            print(f"[!] Initialization Error: Target monitoring path does not exist: {normalized_path}", file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(normalized_path):
            print(f"[!] Initialization Error: Designated path is not a standard file payload: {normalized_path}", file=sys.stderr)
            sys.exit(1)
        return normalized_path

    def process_log_entry(self, raw_line: str) -> None:
        """Parses log string, manages behavioral metrics state window, and enforces triggers."""
        match = self.log_regex.search(raw_line)
        if not match:
            return

        timestamp = match.group("timestamp")
        username = match.group("user")
        source_ip = match.group("ip_address")
        current_epoch = time.time()

        # Input sanitization validation sequence to prevent log injection
        sanitized_ip = re.sub(r"[^\d\.]", "", source_ip)
        sanitized_user = re.sub(r"[^a-zA-Z0-9_\-\.]", "", username)

        # A malformed address that sanitises to nothing cannot be attributed
        # to an actor, so there is nothing to correlate against.
        if not sanitized_ip:
            return

        # Initialize tracking index state if new footprint encountered
        if sanitized_ip not in self.ip_state_history:
            self.ip_state_history[sanitized_ip] = []

        # Update historical access timestamps array
        self.ip_state_history[sanitized_ip].append(current_epoch)

        # Trim timestamps outside the current observation time window
        self.ip_state_history[sanitized_ip] = [
            ts for ts in self.ip_state_history[sanitized_ip]
            if current_epoch - ts <= self.window_seconds
        ]

        # Evaluate threshold conditions
        retained = self.ip_state_history[sanitized_ip]
        if len(retained) < self.threshold_limit:
            # The burst subsided below the threshold, so re-arm the alert for
            # this source. A sustained attack must keep generating findings.
            self.alerted_ips.discard(sanitized_ip)
        elif sanitized_ip not in self.alerted_ips:
            # Dedup: one burst raises one alert, not one per line.
            self.alerted_ips.add(sanitized_ip)
            self.raise_anomaly_alert(sanitized_ip, sanitized_user, timestamp)

    def raise_anomaly_alert(self, ip: str, user: str, log_time: str) -> None:
        """Generates schema normalized JSON alert entities ready for direct enterprise SIEM extraction."""
        alert_payload: Dict[str, Any] = {
            "event_id": "AAIDD-IDENTITY-ANOMALY-01",
            "alert_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_incident_time": log_time,
            "indicators": {
                "attacker_ip": ip,
                "targeted_identity": user
            },
            "risk_assessment": {
                "confidence_rating": "High",
                "classification": "Distributed Authentication Velocity Exploit"
            }
        }
        
        print(f"[CRITICAL ALERT] Behavioral Threshold Crossed by Source footprint: {ip}")
        self.write_to_siem_buffer(alert_payload)

    def write_to_siem_buffer(self, payload: Dict[str, Any]) -> None:
        """Appends telemetry metadata to output storage safely using continuous verification loops."""
        try:
            with open(self.output_json_path, "a", encoding="utf-8") as json_out:
                json_out.write(json.dumps(payload) + "\n")
        except IOError as error:
            print(f"[!] Storage Write Failure: Unable to preserve security telemetry log event: {error}", file=sys.stderr)

    def start_tail_interceptor(self, poll_interval: float = 0.1) -> None:
        """Main active event loop executing real-time ingestion monitoring."""
        print(f"[*] Interceptor Core Active. Monitoring target: {self.target_log_path}")

        try:
            with open(self.target_log_path, "r", encoding="utf-8", errors="ignore") as log_file:
                # Seek to end to monitor live events exclusively
                log_file.seek(0, 2)

                # Holds a trailing fragment that has no newline yet. Without
                # this buffer, a line still being written would be parsed as a
                # short (and usually unmatched) fragment and then discarded.
                buffer = ""

                # Identity of the file we are following, used to detect rotation.
                inode = self._current_inode()

                while True:
                    line = log_file.readline()

                    if not line:
                        # No new data. Check for rotation before sleeping.
                        if self._current_inode() != inode:
                            print("[*] Log rotation detected; reopening target.")
                            log_file.close()
                            log_file = open(
                                self.target_log_path, "r",
                                encoding="utf-8", errors="ignore",
                            )
                            inode = self._current_inode()
                            buffer = ""
                        time.sleep(poll_interval)
                        continue

                    if not line.endswith("\n"):
                        # Incomplete write: keep it and wait for the terminator.
                        buffer += line
                        continue

                    if buffer:
                        line = buffer + line
                        buffer = ""

                    self.process_log_entry(line)

        except KeyboardInterrupt:
            print("\n[*] Sentinel monitoring terminated by operator command execution.")
        except Exception as general_fault:
            print(f"[!] Unhandled operational layer engine crash encountered: {general_fault}", file=sys.stderr)

    def _current_inode(self):
        """Return the inode backing the monitored path, or None if unavailable."""
        try:
            stat_result = os.stat(self.target_log_path)
            # Windows has no stable inode; fall back to the size/mtime pair.
            return (stat_result.st_ino, stat_result.st_dev)
        except OSError:
            return None

if __name__ == "__main__":
    # Resolve paths against the repository root so the engine behaves the same
    # regardless of which directory it is launched from.
    REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    MOCK_LOG = os.environ.get("AAIDD_LOG_PATH", os.path.join(REPO_ROOT, "auth.log"))
    OUTPUT_METRICS = os.path.join(REPO_ROOT, "telemetry_siem", "sample_alerts.json")

    # Pre-flight confirmation initialization check
    if not os.path.exists(MOCK_LOG):
        with open(MOCK_LOG, "w", encoding="utf-8") as f:
            f.write("Jun 15 12:00:00 sandbox sshd[1000]: Server initialization complete.\n")

    engine = LogInterceptorSentinel(MOCK_LOG, OUTPUT_METRICS)
    engine.start_tail_interceptor()
