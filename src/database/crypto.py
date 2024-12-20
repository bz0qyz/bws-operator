import uuid
import json
import base64
import hashlib
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend


class Crypto:
    def __init__(self, key=None, no_encrypt=False):
        self.logger = logging.getLogger(__name__)
        self.key = self.__string_to_fernet_key__(key, b"8025") or self.generate_key()
        self.cipher = Fernet(self.key)
        self.no_encrypt = no_encrypt

    def __string_to_fernet_key__(self, key: str, salt: bytes) -> bytes:
        # PBKDF2 parameters
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        encoded_key = kdf.derive(key.encode())  # Derive a 32-byte key
        return base64.urlsafe_b64encode(encoded_key)  # Encode the key in base64 for Fernet

    def generate_key(self):
        gen_key =  base64.urlsafe_b64encode(uuid.uuid4().bytes)
        #gen_key = Fernet.generate_key()
        self.logger.warning(f"Generated new encryption key: {gen_key}")
        return gen_key

    def encrypt(self, data: str):
        if self.no_encrypt:
            return data

        if isinstance(data, dict) or isinstance(data, list):
            data = json.dumps(data)

        return base64.b64encode(
            self.cipher.encrypt(f"{data}".encode("utf-8"))).decode("utf-8")
        # return self.cipher.encrypt(data.encode())

    def decrypt(self, data: bytes):
        if self.no_encrypt:
            return data

        decoded_data = base64.b64decode(data)
        # if the decoded_value is json, convert it to a dict
        try:
            decoded_data = json.loads(decoded_data)
        except:
            pass
        return self.cipher.decrypt(decoded_data).decode("utf-8")

    async def hashstr(self, data: str):
        return hashlib.sha256(data.encode()).hexdigest()


