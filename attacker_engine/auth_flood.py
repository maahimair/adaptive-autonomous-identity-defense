# attacker_engine/auth_flood.py
# AAIDD — Authentication Flood Simulator
#
# Lab-only tool used to generate the failed-login telemetry that
# defender_engine/log_sentinel.py detects against. It targets loopback by
# default and refuses to run against anything else unless explicitly told to.
#
# This is a controlled validation harness, not an attack tool. Keep it pointed
# at disposable lab infrastructure only.

import sys
import threading
import time
from typing import List

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


class LabTargetNotAllowedError(PermissionError):
    """Raised when the simulator is pointed outside the lab boundary."""


class SecurityAttackSimulator:
    """Drives concurrent SSH authentication attempts against a lab target."""

    # Only these destinations are permitted without an explicit override.
    PERMITTED_HOSTS = {"127.0.0.1", "localhost", "::1"}

    def __init__(self, target_ip: str, target_port: int, username: str,
                 password_list: List[str], allow_remote: bool = False,
                 known_host_key_path: str = None):
        if not allow_remote and target_ip not in self.PERMITTED_HOSTS:
            raise LabTargetNotAllowedError(
                f"Refusing to target {target_ip!r}. This simulator is restricted "
                f"to loopback ({', '.join(sorted(self.PERMITTED_HOSTS))}). "
                "Pass allow_remote=True only for isolated disposable lab hosts."
            )

        self.target_ip = target_ip
        self.target_port = target_port
        self.username = username
        self.password_list = password_list
        self.known_host_key_path = known_host_key_path
        self.thread_lock = threading.Lock()

        # Only count what actually happened, so a run can assert on results.
        self.attempts = 0
        self.failures = 0
        self.successes = 0

    def attempt_login(self, password: str) -> None:
        """Attempts a single SSH authentication connection with explicit safety limits."""
        ssh_client = paramiko.SSHClient()

        if self.known_host_key_path:
            # Known-hosts verification: refuse a key we have never seen, and
            # refuse a key that CHANGED, so a MITM cannot silently sit in the
            # middle of the lab connection.
            ssh_client.load_host_keys(self.known_host_key_path)
            ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            # No known-hosts file available. Rejecting every unknown key would
            # make first-run lab setup impossible, so surface the gap loudly
            # instead of trusting whatever answers.
            print(
                "[!] WARNING: no known_hosts file supplied; host key will not be "
                "verified. Supply known_hosts_path for any non-loopback target.",
                file=sys.stderr,
            )
            ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())

        try:
            # Enforce short timeouts to prevent hanging resources
            ssh_client.connect(
                hostname=self.target_ip,
                port=self.target_port,
                username=self.username,
                password=password,
                timeout=2.0,
                banner_timeout=2.0,
                auth_timeout=2.0,
                allow_agent=False,
                look_for_keys=False,
            )

            with self.thread_lock:
                self.attempts += 1
                self.successes += 1
                # Log the username and outcome only. Writing the attempted
                # password to stdout puts a usable credential in terminal
                # scrollback, shell history and CI logs.
                print(f"[+] Authentication SUCCEEDED for '{self.username}' "
                      f"(password #{self.attempts})")
            ssh_client.close()

        except paramiko.AuthenticationException:
            with self.thread_lock:
                self.attempts += 1
                self.failures += 1
                print(f"[-] Authentication failed for '{self.username}' "
                      f"(attempt {self.attempts})")

        except paramiko.BadHostKeyException as error:
            with self.thread_lock:
                self.attempts += 1
                self.failures += 1
                print(f"[!] HOST KEY MISMATCH for {self.target_ip}: {error}. "
                      "Refusing to continue — possible interception.",
                      file=sys.stderr)

        except (paramiko.SSHException, OSError) as error:
            with self.thread_lock:
                self.attempts += 1
                self.failures += 1
                print(f"[!] Network/protocol error on attempt "
                      f"{self.attempts + 1} against "
                      f"{self.target_ip}:{self.target_port}: {error}",
                      file=sys.stderr)

        finally:
            ssh_client.close()

    def execute_flood(self) -> dict:
        """Spawns concurrent execution threads to simulate a distributed stress event."""
        if not PARAMIKO_AVAILABLE:
            print("[!] paramiko is not installed. "
                  "Run: pip install -r requirements.txt", file=sys.stderr)
            return {"attempts": 0, "failures": 0, "successes": 0}

        print(f"[*] Commencing lab authentication flood against "
              f"{self.target_ip}:{self.target_port} "
              f"({len(self.password_list)} attempts)")

        threads = [
            threading.Thread(target=self.attempt_login, args=(pwd,), daemon=True)
            for pwd in self.password_list
        ]

        for worker in threads:
            worker.start()
            # Small delay to preserve local system stability
            time.sleep(0.1)

        for worker in threads:
            worker.join()

        summary = {
            "attempts": self.attempts,
            "failures": self.failures,
            "successes": self.successes,
        }
        print(f"[*] Simulation complete — {summary['attempts']} attempts, "
              f"{summary['failures']} failed, {summary['successes']} succeeded.")
        return summary


if __name__ == "__main__":
    # Safe lab defaults.
    TARGET = "127.0.0.1"
    PORT = 2222
    USER = "root"
    PASSWORDS = ["123456", "password", "admin", "secret", "guest", "root123"]

    # A successful login against a real host is a finding, not a win. Uncomment
    # the stop so a lab mistake cannot keep going.
    # if simulator.successes:
    #     print("[!] Valid credentials found — stopping immediately.")

    simulator = SecurityAttackSimulator(TARGET, PORT, USER, PASSWORDS)
    simulator.execute_flood()