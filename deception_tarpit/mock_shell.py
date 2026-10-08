# deception_tarpit/mock_shell.py
# AAIDD — Adaptive Deception Tarpit
#
# Presents a fake interactive shell to a trapped attacker and records every
# command they run. Nothing here touches the real filesystem, executes
# anything, or connects to a network: the entire "host" is an in-memory dict.

import json
import os
import sys
import time
from typing import Any, Dict, List


class AdaptiveDeceptionTarpit:
    """An isolated, fake shell environment that logs attacker activity."""

    def __init__(self, output_telemetry_path: str, max_commands: int = 500):
        self.output_telemetry_path = output_telemetry_path

        # Mimic a standard corporate production environment string.
        self.prompt_string = "ubuntu@prod-db-server:~$ "

        # Cap the audit trail so a patient attacker cannot fill the disk.
        self.max_commands = max_commands
        self.command_count = 0

        # Fake filesystem used for navigation simulation. Paths are the only
        # keys accepted; everything else is reported as missing.
        self.mock_file_system: Dict[str, List[str]] = {
            "/": ["bin", "etc", "home", "var", "root", "opt"],
            "/bin": ["bash", "cat", "ls", "ps", "id", "sudo", "wget"],
            "/etc": ["passwd", "hosts", "ssh"],
            "/etc/ssh": ["sshd_config", "ssh_host_rsa_key"],
            "/home/ubuntu": ["db_backup.sql", "config.json", ".bash_history"],
            "/var": ["log", "www"],
            "/var/log": ["auth.log", "syslog"],
            "/root": [],
            "/opt": [],
        }

        self.current_working_directory = "/home/ubuntu"

    # ── Telemetry ─────────────────────────────────────────────────────────────

    def log_attacker_action(self, input_command: str) -> None:
        """Appends every captured command to the JSONL telemetry trail."""
        self.command_count += 1
        telemetry_payload: Dict[str, Any] = {
            "event_id": "AAIDD-DECEPTION-ENGAGEMENT-02",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "captured_input": input_command.strip(),
            "environment_state": {
                "active_directory": self.current_working_directory,
                "session_status": "Trapped",
                "command_sequence": self.command_count,
            },
        }

        try:
            parent = os.path.dirname(self.output_telemetry_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(self.output_telemetry_path, "a", encoding="utf-8") as out_file:
                out_file.write(json.dumps(telemetry_payload) + "\n")
        except (OSError, ValueError) as error:
            # Telemetry loss must never hand the attacker a real shell.
            # ValueError covers a malformed path (embedded null, and so on),
            # which os.makedirs raises rather than OSError.
            print(f"[!] Telemetry write failed: {error}", file=sys.stderr)

    # ── Path helpers ──────────────────────────────────────────────────────────

    def _path_exists(self, target: str) -> bool:
        """True when `target` is a known simulated directory or a listed file."""
        if target in self.mock_file_system:
            return True
        parent, _, name = target.rpartition("/")
        listing = self.mock_file_system.get(parent or "/")
        return bool(listing) and name in listing

    @staticmethod
    def _normalise(base: str, target: str) -> str:
        """Resolve `target` against `base` without touching the real filesystem."""
        if target.startswith("/"):
            candidate = target
        else:
            candidate = os.path.join(base, target)

        # Purely lexical: collapse . and .. so a crafted path cannot escape the
        # simulated tree into the host filesystem.
        parts: List[str] = []
        for segment in candidate.split("/"):
            if segment in ("", "."):
                continue
            if segment == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(segment)

        return "/" + "/".join(parts)

    # ── Command handling ──────────────────────────────────────────────────────

    def process_command(self, raw_command: str) -> str:
        """Evaluates one command and returns the fake output to display."""
        tokens = raw_command.strip().split()
        if not tokens:
            return ""

        base_cmd = tokens[0].lower()
        args = tokens[1:]

        if base_cmd == "exit":
            raise SystemExit(0)

        if base_cmd == "cd":
            if not args:
                return self.current_working_directory
            target = self._normalise(self.current_working_directory, args[0])
            if target in self.mock_file_system:
                self.current_working_directory = target
                return ""
            return f"cd: {args[0]}: No such file or directory"

        if base_cmd == "pwd":
            return self.current_working_directory

        if base_cmd == "ls":
            if args:
                target = self._normalise(self.current_working_directory, args[0])
                listing = self.mock_file_system.get(target)
                if listing is not None:
                    return "\n".join(listing)
                # A file, not a directory: `ls somefile` prints the name.
                if self._path_exists(target):
                    return target.rpartition("/")[2]
                return f"ls: cannot access '{args[0]}': No such file or directory"
            return "\n".join(
                self.mock_file_system.get(self.current_working_directory, [])
            )

        if base_cmd in ("whoami", "id"):
            return "ubuntu" if base_cmd == "whoami" else "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)"

        if base_cmd == "hostname":
            return "prod-db-server"

        if base_cmd == "cat":
            if not args:
                return "cat: missing operand"
            target = self._normalise(self.current_working_directory, args[0])
            if not self._path_exists(target):
                return f"cat: {args[0]}: No such file or directory"
            # Decoy content. Deliberately fake so nothing useful is disclosed.
            if target == "/etc/passwd":
                return (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"
                )
            if target == "/etc/ssh/sshd_config":
                return "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes"
            return "(binary or empty file)"

        if base_cmd == "uname":
            return "-a" if args else "Linux"

        if base_cmd == "ps":
            return (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:01 systemd\n"
                " 1042 pts/0    00:00:00 bash\n"
                " 1188 ?        00:00:03 postgres\n"
                " 1203 ?        00:00:00 nginx"
            )

        if base_cmd == "env":
            return (
                "USER=ubuntu\n"
                "HOME=/home/ubuntu\n"
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "DB_HOST=10.4.2.19\n"
                "DB_NAME=orders_production"
            )

        if base_cmd in ("sudo", "su"):
            # Tempting but useless: the attacker believes privilege escalation
            # is progressing while nothing actually happens.
            if base_cmd == "su":
                return "Password: \nsu: Authentication failure"
            return (
                "[sudo] password for ubuntu: \n"
                "Sorry, try again.\n"
                "Sorry, try again.\n"
                "sudo: 3 incorrect password attempts"
            )

        if base_cmd in ("echo", "cat ", "rm", "wget", "curl", "chmod", "history"):
            if base_cmd == "echo":
                return " ".join(args)
            if base_cmd == "history":
                return "  1  ls -la\n  2  cd /etc\n  3  cat passwd"
            if base_cmd == "rm":
                return ""  # Pretend the destructive command succeeded.
            return base_cmd + ": command not found"

        return f"{base_cmd}: command not found"

    # ── Interactive loop ──────────────────────────────────────────────────────

    def enter_shell_loop(self) -> None:
        """Runs the interactive session until the operator or attacker exits."""
        print("[*] Adaptive deception tarpit deployed.")
        print("Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)")
        print(" * Documentation:  https://ubuntu.com\n")

        try:
            while True:
                try:
                    user_input = input(self.prompt_string)
                except EOFError:
                    # Non-interactive stdin: exercise the handler without
                    # blocking a terminal forever.
                    print("\n[!] No interactive input available; exiting tarpit.")
                    break

                self.log_attacker_action(user_input)

                try:
                    execution_output = self.process_command(user_input)
                except SystemExit:
                    print("logout")
                    break

                if execution_output:
                    print(execution_output)

        except KeyboardInterrupt:
            print("\n[*] Tarpit session terminated by operator.")


if __name__ == "__main__":
    TELEMETRY_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "telemetry_siem",
        "sample_alerts.json",
    )

    tarpit_session = AdaptiveDeceptionTarpit(TELEMETRY_PATH)
    tarpit_session.enter_shell_loop()