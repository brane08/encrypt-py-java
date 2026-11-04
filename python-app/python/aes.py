import base64
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_ENV = "AES_KEY_B64"


def load_key(env: str = KEY_ENV) -> bytes:
    """Read a base64-encoded 32-byte key from the environment."""
    value = os.environ.get(env)
    if not value:
        raise RuntimeError(f"{env} is not set (generate one: python aes.py --gen-key)")
    key = base64.b64decode(value)
    if len(key) != 32:
        raise RuntimeError(f"{env} must decode to 32 bytes, got {len(key)}")
    return key


class AESCipher:
    """AES-256-GCM. Payload = base64(nonce(12) || ciphertext || tag(16))."""

    nonce_size = 12

    def __init__(self, key: bytes):
        self._aead = AESGCM(key)

    @classmethod
    def from_env(cls, env: str = KEY_ENV) -> "AESCipher":
        return cls(load_key(env))

    def encrypt(self, raw: str) -> str:
        nonce = os.urandom(self.nonce_size)
        ct = self._aead.encrypt(nonce, raw.encode("utf-8"), None)
        return base64.b64encode(nonce + ct).decode("ascii")

    def decrypt(self, enc: str) -> str:
        data = base64.b64decode(enc)
        nonce, ct = data[:self.nonce_size], data[self.nonce_size:]
        return self._aead.decrypt(nonce, ct, None).decode("utf-8")


if __name__ == "__main__":
    if "--gen-key" in sys.argv:
        print(base64.b64encode(AESGCM.generate_key(bit_length=256)).decode("ascii"))
        sys.exit(0)
    cipher = AESCipher.from_env()
    if len(sys.argv) > 1:
        # decrypt a payload produced elsewhere (e.g. Java)
        print(cipher.decrypt(sys.argv[1]))
    else:
        payload = cipher.encrypt("SomePassword")
        print(payload)
        print(cipher.decrypt(payload))
