import hashlib
from .interfaces import HashInterface

class SHA256Impl(HashInterface):
    def digest(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

class SHA384Impl(HashInterface):
    def digest(self, data: bytes) -> bytes:
        return hashlib.sha384(data).digest()
