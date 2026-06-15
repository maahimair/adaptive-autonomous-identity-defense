import os
import re
import sys
import json
import time
from typing import Dict, Any

class LogInterceptorSentinel:
    def __init__(self, target_log_path: str, output_json_path: str):
        self.target_log_path = self.verify_safe_path(target_log_path)
        self.output_json_path = output_json_path
        
        # Matches standard Linux auth.log structural formats safely
        self.log_regex = re.compile(
            r"(?P<timestamp>\b[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\b).*?"
            r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip_address>\S+)"
        )
        
        # State tracker to record behavioral timestamps per IP
        self.ip_state_history: Dict[str, list] = {}
        self.threshold_limit = 3  # Maximum failures permitted
        self.window_seconds = 10.0 # Time horizon for tracking

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
        if len(self.ip_state_history[sanitized_ip]) >= self.threshold_limit:
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

    def start_tail_interceptor(self) -> None:
        """Main active event loop executing real-time ingestion monitoring."""
        print(f"[*] Interceptor Core Active. Monitoring target: {self.target_log_path}")
        try:
            with open(self.target_log_path, "r", encoding="utf-8", errors="ignore") as log_file:
                # Seek to end to monitor live events exclusively
                log_file.seek(0, 2)
                while True:
                    line = log_file.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    self.process_log_entry(line)
        except KeyboardInterrupt:
            print("\n[*] Sentinel monitoring terminated by operator command execution.")
        except Exception as general_fault:
            print(f"[!] Unhandled operational layer engine crash encountered: {general_fault}", file=sys.stderr)

if __name__ == "__main__":
    # Local simulation parameters
    MOCK_LOG = "auth.log"
    OUTPUT_METRICS = "telemetry_siem/sample_alerts.json"

    # Pre-flight confirmation initialization check
    if not os.path.exists(MOCK_LOG):
        with open(MOCK_LOG, "w") as f:
            f.write("Jun 15 12:00:00 sandbox sshd[1000]: Server initialization complete.\n")

    os.makedirs(os.path.dirname(OUTPUT_METRICS), exist_ok=True)
    
    engine = LogInterceptorSentinel(MOCK_LOG, OUTPUT_METRICS)
    engine.start_tail_interceptor()
