import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from .interfaces import AEADInterface

class AESGCMImpl(AEADInterface):
    def __init__(self):
        pass

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """
        Encrypts plaintext using the given key and associated data.
        Generates a random 12-byte nonce.
        Returns nonce + tag + ciphertext.
        """
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
        tag = ct_and_tag[-16:]
        ciphertext = ct_and_tag[:-16]
        return nonce + tag + ciphertext

    def decrypt(self, key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """
        Decrypts ciphertext using the given key and associated data.
        Expects nonce(12) + tag(16) + ciphertext.
        Returns plaintext.
        """
        if len(ciphertext) < 28:
            raise ValueError("Ciphertext too short")
        
        nonce = ciphertext[:12]
        tag = ciphertext[12:28]
        actual_ciphertext = ciphertext[28:]
        
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, actual_ciphertext + tag, aad)

class ChaCha20Poly1305Impl(AEADInterface):
    def __init__(self):
        pass

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """
        Encrypts plaintext using the given key and associated data.
        Generates a random 12-byte nonce.
        Returns nonce + ciphertext (which includes the tag).
        """
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    def decrypt(self, key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """
        Decrypts ciphertext using the given key and associated data.
        Expects the first 12 bytes of ciphertext to be the nonce.
        Returns plaintext.
        """
        if len(ciphertext) < 12:
            raise ValueError("Ciphertext too short")
        
        nonce = ciphertext[:12]
        actual_ciphertext = ciphertext[12:]
        
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, actual_ciphertext, aad)
