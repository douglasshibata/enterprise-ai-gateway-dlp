import os
import time
import base64
import json
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class EncryptedSessionVault:
    """
    AES-256-GCM encrypted tokenization vault with 24-hour TTL
    for reversible pseudonymization.
    """
    def __init__(self, key: Optional[bytes] = None, ttl_seconds: int = 86400):
        self.key = key or AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)
        self.ttl_seconds = ttl_seconds
        self.storage: Dict[str, Dict[str, Any]] = {}

    def store_mapping(self, session_id: str, mapping: Dict[str, str]):
        nonce = os.urandom(12)
        serialized = json.dumps(mapping).encode("utf-8")
        ciphertext = self.aesgcm.encrypt(nonce, serialized, None)

        self.storage[session_id] = {
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "data": base64.b64encode(ciphertext).decode("utf-8"),
            "expires_at": time.time() + self.ttl_seconds
        }

    def retrieve_mapping(self, session_id: str) -> Dict[str, str]:
        entry = self.storage.get(session_id)
        if not entry:
            return {}

        if time.time() > entry["expires_at"]:
            del self.storage[session_id]
            return {}

        nonce = base64.b64decode(entry["nonce"])
        ciphertext = base64.b64decode(entry["data"])
        decrypted = self.aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(decrypted.decode("utf-8"))

    def rehydrate_text(self, session_id: str, text: str) -> str:
        mapping = self.retrieve_mapping(session_id)
        rehydrated = text
        for token, original in mapping.items():
            rehydrated = rehydrated.replace(token, original)
        return rehydrated
