import os
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

from .interfaces import KEMInterface

class P256HKDFKEM(KEMInterface):
    """
    P-256 KEM with a strict, SGX-friendly encoding:
      - pkU: 65-byte uncompressed point: 0x04 || X(32 BE) || Y(32 BE)
      - skU: 32-byte private scalar in big-endian
      - ct:  65-byte uncompressed ephemeral public key in the same format
      - shared secret: SHA256(ECDH_x_be) (matches SGX enclave derivation)

    This format is enforced to match the SGX worker/enclave expectation and to avoid
    accidental DER/PEM/compressed-point mismatches in evaluation.
    """
    def __init__(self):
        self._salt = b""
        self._info = b"openwhisk-confidential-kem-p256"
        self._length = 32

    def keygen(self) -> Tuple[bytes, bytes]:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        sk_int = private_key.private_numbers().private_value
        sk_bytes = sk_int.to_bytes(32, "big")

        pk_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return pk_bytes, sk_bytes

    def encap(self, pk: bytes) -> Tuple[bytes, bytes]:
        if len(pk) != 65 or pk[0] != 0x04:
            raise ValueError("P-256 pk must be 65-byte uncompressed point (0x04||X||Y)")
        recipient_pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk)

        ephemeral_sk = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_pk = ephemeral_sk.public_key()

        shared_secret_raw = ephemeral_sk.exchange(ec.ECDH(), recipient_pk)
        # Match SGX `sgx_ec256_dh_shared_t` byte order (little-endian).
        shared_secret_raw = shared_secret_raw[::-1]

        shared_secret = hashlib.sha256(shared_secret_raw).digest()

        ct = ephemeral_pk.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return ct, shared_secret

    def decap(self, sk: bytes, ct: bytes) -> bytes:
        if len(sk) != 32:
            raise ValueError("P-256 sk must be 32-byte scalar (big-endian)")
        if len(ct) != 65 or ct[0] != 0x04:
            raise ValueError("P-256 ct must be 65-byte uncompressed point (0x04||X||Y)")

        sk_int = int.from_bytes(sk, "big")
        private_key = ec.derive_private_key(sk_int, ec.SECP256R1(), default_backend())
        ephemeral_pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ct)

        shared_secret_raw = private_key.exchange(ec.ECDH(), ephemeral_pk)
        # Match SGX `sgx_ec256_dh_shared_t` byte order (little-endian).
        shared_secret_raw = shared_secret_raw[::-1]

        return hashlib.sha256(shared_secret_raw).digest()

class X25519HKDFKEM(KEMInterface):
    def __init__(self):
        self._salt = b"" # Fixed empty salt for simplicity, or could be random if transmitted
        self._info = b"openwhisk-confidential-kem"
        self._length = 32 # Length of the derived key (e.g., for AES-256)

    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generates a public/private key pair.
        Returns (pk, sk) as raw bytes.
        """
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        sk_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pk_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return pk_bytes, sk_bytes

    def encap(self, pk: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulates a shared secret for the given public key.
        Returns (ciphertext, shared_secret).
        Ciphertext is the ephemeral public key.
        """
        # Deserialize recipient's public key
        recipient_pk = x25519.X25519PublicKey.from_public_bytes(pk)

        # Generate ephemeral key pair
        ephemeral_sk = x25519.X25519PrivateKey.generate()
        ephemeral_pk = ephemeral_sk.public_key()

        # Perform ECDH
        shared_secret_raw = ephemeral_sk.exchange(recipient_pk)

        # Derive shared key using HKDF
        # We include the ephemeral public key and recipient public key in the HKDF input 
        # (or just the shared secret, but binding to keys is safer). 
        # For this implementation, we'll stick to standard HKDF on the shared secret.
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self._length,
            salt=self._salt,
            info=self._info,
        )
        shared_key = hkdf.derive(shared_secret_raw)

        # Serialize ephemeral public key (this is the ciphertext)
        ciphertext = ephemeral_pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return ciphertext, shared_key

    def decap(self, sk: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulates the shared secret using the private key.
        Returns shared_secret.
        """
        # Deserialize recipient's private key
        recipient_sk = x25519.X25519PrivateKey.from_private_bytes(sk)

        # Deserialize ephemeral public key (ciphertext)
        ephemeral_pk = x25519.X25519PublicKey.from_public_bytes(ciphertext)

        # Perform ECDH
        shared_secret_raw = recipient_sk.exchange(ephemeral_pk)

        # Derive shared key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self._length,
            salt=self._salt,
            info=self._info,
        )
        shared_key = hkdf.derive(shared_secret_raw)

        return shared_key
