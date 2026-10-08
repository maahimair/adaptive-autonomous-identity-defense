# threat_swarm/swarm_sync.py
# AAIDD — Collaborative Threat Swarm Sync Client
#
# Packages a confirmed malicious indicator, signs it with an HMAC so a sibling
# node can verify the sender, and broadcasts it to the central blocklist
# registry so neighbouring services can immunise against the same actor.

import hashlib
import hmac
import json
import os
import sys
import time
from typing import Any, Dict


class ThreatSwarmSyncClient:
    def __init__(self, node_id: str, shared_secret_key: str,
                 registry_api_url: str, timeout: float = 5.0):
        if not shared_secret_key:
            # Fail closed. An empty key still produces a valid HMAC, which
            # would let anyone forge threat intelligence that other nodes trust.
            raise ValueError("shared_secret_key must not be empty")

        self.node_id = node_id
        self.secret_key = shared_secret_key.encode("utf-8")
        self.registry_api_url = registry_api_url
        self.timeout = timeout

    def generate_secure_signature(self, serialized_data: str) -> str:
        """Signs the payload so the registry can verify this node's identity."""
        return hmac.new(
            self.secret_key, serialized_data.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def verify_signature(self, serialized_data: str, signature: str) -> bool:
        """Constant-time check of a signature returned by the registry."""
        return hmac.compare_digest(
            self.generate_secure_signature(serialized_data), signature
        )

    def build_packet(self, bad_ip: str, classification_type: str) -> Dict[str, Any]:
        """Builds the signed transmission packet without sending it."""
        threat_payload: Dict[str, Any] = {
            "origin_node": self.node_id,
            "timestamp": int(time.time()),
            "threat_actor_ip": bad_ip,
            "attack_classification": classification_type,
        }

        # Canonical serialisation: the signature only verifies if the registry
        # re-serialises with identical key ordering and separators.
        serialized_payload = json.dumps(threat_payload, sort_keys=True)

        return {
            "secure_signature": self.generate_secure_signature(serialized_payload),
            "payload": threat_payload,
        }

    def broadcast_malicious_indicator(self, bad_ip: str,
                                      classification_type: str,
                                      dry_run: bool = False) -> bool:
        """Packages, signs and transmits threat telemetry to the central swarm."""
        if not bad_ip:
            print("[!] Refusing to broadcast an empty indicator.", file=sys.stderr)
            return False

        transmission_packet = self.build_packet(bad_ip, classification_type)

        print(f"[*] Packaging indicator of compromise: {bad_ip}")
        print(f"[*] Payload signature: {transmission_packet['secure_signature']}")

        if dry_run:
            # Local validation loop: exercise signing without a live registry.
            print("[*] dry_run set — printing packet instead of transmitting:")
            print(json.dumps(transmission_packet, indent=2))
            return True

        try:
            import requests

            response = requests.post(
                self.registry_api_url,
                json=transmission_packet,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
            response.raise_for_status()

        except ImportError:
            print("[!] requests is not installed. "
                  "Run: pip install -r requirements.txt", file=sys.stderr)
            return False

        except Exception as error:
            # requests raises many concrete subclasses; catching the base keeps
            # the caller simple. The detail is logged, never returned as 200.
            print(f"[!] Broadcast failed for {bad_ip}: {error}", file=sys.stderr)
            return False

        print(f"[+] Broadcast delivered to swarm registry "
              f"(HTTP {response.status_code}).")
        return True


if __name__ == "__main__":
    # Shared secret comes from the environment. A hardcoded default would make
    # every deployment of this repo forgeable.
    NODE = os.environ.get("AAIDD_NODE_ID", "Helsinki-Edge-Node-01")
    SECRET = os.environ.get("AAIDD_SWARM_SECRET", "")
    MOCK_API = os.environ.get(
        "AAIDD_REGISTRY_URL", "https://threatswarm-registry.local"
    )

    if not SECRET:
        print("[!] AAIDD_SWARM_SECRET is not set.", file=sys.stderr)
        print("[!] Export the per-node HMAC secret, for example:", file=sys.stderr)
        print("[!]   export AAIDD_SWARM_SECRET=\"$(openssl rand -hex 32)\"",
              file=sys.stderr)
        sys.exit(1)

    sync_client = ThreatSwarmSyncClient(NODE, SECRET, MOCK_API)

    # Default to a dry run so running the script never pushes live IoCs to a
    # registry by accident. Pass --live to transmit for real.
    dry_run = "--live" not in sys.argv

    if not dry_run:
        print("[!] LIVE mode: this will broadcast a real indicator.")

    sync_client.broadcast_malicious_indicator(
        "198.51.100.42",           # TEST-NET-2, reserved for documentation
        "Distributed Authentication Velocity Exploit",
        dry_run=dry_run,
    )