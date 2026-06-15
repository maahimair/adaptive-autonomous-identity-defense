import sys
import os
import time
import json
from typing import Dict, Any

class AdaptiveDeceptionTarpit:
    def __init__(self, output_telemetry_path: str):
        self.output_telemetry_path = output_telemetry_path
        # Mimic a standard corporate production environment string
        self.prompt_string = "ubuntu@prod-db-server:~$ "
        
        # Fake file system to track if they try to browse around
        self.mock_file_system = {
            "/": ["bin", "etc", "home", "var", "root", "opt"],
            "/home/ubuntu": ["db_backup.sql", "config.json", ".bash_history"],
            "/etc": ["passwd", "hosts", "ssh"],
            "/root": []
        }
        self.current_working_directory = "/home/ubuntu"

    def log_attacker_action(self, input_command: str) -> None:
        """Saves every terminal keystroke and input command into a telemetry audit trail."""
        telemetry_payload: Dict[str, Any] = {
            "event_id": "AAIDD-DECEPTION-ENGAGEMENT-02",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "captured_input": input_command.strip(),
            "environment_state": {
                "active_directory": self.current_working_directory,
                "session_status": "Trapped"
            }
        }
        
        try:
            with open(self.output_telemetry_path, "a", encoding="utf-8") as out_file:
                out_file.write(json.dumps(telemetry_payload) + "\n")
        except IOError as error:
            print(f"[!] Target logging error encountered: {error}", file=sys.stderr)

    def process_command(self, raw_command: str) -> str:
        """Processes the trapped input command and generates safe, fake server returns."""
        tokens = raw_command.strip().split()
        if not tokens:
            return ""
            
        base_cmd = tokens[0].lower()

        # Handle navigation command simulation securely
        if base_cmd == "cd":
            if len(tokens)  None:
        """Starts the interactive shell execution context loop."""
        print(f"[*] Starting honeypot shell layer deployment context framework.")
        print("Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)")
        print(" * Documentation:  https://ubuntu.com\n")
        
        try:
            while True:
                user_input = input(self.prompt_string)
                
                # Instantly record malicious actions to the audit registry 
                self.log_attacker_action(user_input)
                
                # Process structural returns
                execution_output = self.process_command(user_input)
                if execution_output:
                    print(execution_output)
                    
        except (KeyboardInterrupt, EOFError):
            print("\nTarpit runtime system interface instance closed by platform administrator.")

if __name__ == "__main__":
    AUDIT_OUTPUT = "telemetry_siem/sample_alerts.json"
    os.makedirs(os.path.dirname(AUDIT_OUTPUT), exist_ok=True)
    
    tarpit_session = AdaptiveDeceptionTarpit(AUDIT_OUTPUT)
    tarpit_session.enter_shell_loop()
