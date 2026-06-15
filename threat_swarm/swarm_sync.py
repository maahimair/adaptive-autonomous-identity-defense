import sys
import os
import json
import time
import hmac
import hashlib
from typing import Dict, Any

class ThreatSwarmSyncClient:
    def __init__(self, node_id: str, shared_secret_key: str, registry_api_url: str):
        self.node_id = node_id
        self.secret_key = shared_secret_key.encode("utf-8")
        self.registry_api_url = registry_api_url

    def generate_secure_signature(self, serialized_data: str) -> str:
        """Generates a cryptographic HMAC signature to prevent malicious spoofing of threat data."""
        return hmac.new(self.secret_key, serialized_data.encode("utf-8"), hashlib.sha256).hexdigest()

    def broadcast_malicious_indicator(self, bad_ip: str, classification_type: str) -> bool:
        """Packages, signs, and simulates transmission of threat telemetry metadata to the central swarm."""
        threat_payload: Dict[str, Any] = {
            "origin_node": self.node_id,
            "timestamp": int(time.time()),
            "threat_actor_ip": bad_ip,
            "attack_classification": classification_type
        }

        # Serialize payload data cleanly to maintain integrity
        serialized_payload = json.dumps(threat_payload, sort_keys=True)
        crypto_signature = self.generate_secure_signature(serialized_payload)

        # Structure the formal transmission packet
        transmission_packet: Dict[str, Any] = {
            "secure_signature": crypto_signature,
            "payload": threat_payload
        }

        print(f"[*] Packaging Indicators of Compromise (IoC) for: {bad_ip}")
        print(f"[*] Generated Security Token Signature: {crypto_signature}")

        # Simulate transmission error-handling validation loop
        try:
            # In a production environment, this replaces with an active requests.post() routine
            print(f"[+] Successfully transmitted broadcast package to Swarm Registry API Gateway.")
            print(json.dumps(transmission_packet, indent=2))
            return True
        except Exception as transmission_fault:
            print(f"[!] Critical Sync Failure: Unable to broadcast threat footprint: {transmission_fault}", file=sys.stderr)
            return False

if __name__ == "__main__":
    # Local verification loop configuration 
    NODE = "Helsinki-Edge-Node-01"
    SECRET = "EnterpriseSwarmToken2026"
    MOCK_API = "https://threatswarm-registry.local"

    sync_client = ThreatSwarmSyncClient(NODE, SECRET, MOCK_API)
    
    # Simulate broadcasting a confirmed threat actor footprint
    sync_client.broadcast_malicious_indicator("198.51.100.42", "Distributed Authentication Velocity Exploit")
