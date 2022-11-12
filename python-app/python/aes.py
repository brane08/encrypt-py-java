import base64

from Crypto.Cipher import AES


class AESCipher:
    iv_value = b"\x4d\x6a\x43\x64\x4a\x65\x4c\x71\x6b\x76\x4e\x29\x73\x78\x48\x35"

    key_value = b"\x59\x79\x4c\x44\x68\x35\x34\x4b\x51\x4f\x76\x24\x62\x50\x61\x46" \
                b"\x6b\x4a\x5a\x66\x77\x6f\x70\x36\x21\x25\x53\x4d\x6a\x55\x6d\x6c"
    block_size = 16
    pad = lambda s: bytes(s + (AESCipher.block_size - len(s) % AESCipher.block_size) * chr(
        AESCipher.block_size - len(s) % AESCipher.block_size), "utf-8")
    unpad = lambda s: s[0:-ord(s[-1:])]

    @classmethod
    def encrypt(cls, raw: str):
        raw = cls.pad(raw)
        cipher = AES.new(cls.key_value, AES.MODE_CBC, cls.iv_value)
        return base64.b64encode(cipher.encrypt(raw)).decode("utf-8")

    @classmethod
    def decrypt(cls, enc: str):
        enc = base64.b64decode(enc)
        cipher = AES.new(cls.key_value, AES.MODE_CBC, cls.iv_value)
        d = cipher.decrypt(enc)
        return cls.unpad(d).decode("utf-8")


if __name__ == "__main__":
    message = "hello_world"
    encrypted_message = AESCipher.encrypt(message)
    print(encrypted_message)
    decrypted_message = AESCipher.decrypt("32xtar3ZkpRG9rHQfTK9aw==")
    print(decrypted_message)
