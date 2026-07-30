from typing import Tuple, Any
from .interfaces import IBEInterface
from py_ecc.bn128 import G1, G2, multiply, add, pairing, curve_order, FQ, FQ2
import hashlib
import os
import pickle
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def to_primitive(obj):
    if hasattr(obj, 'coeffs'):
        return tuple(to_primitive(c) for c in obj.coeffs)
    if isinstance(obj, tuple):
        return tuple(to_primitive(x) for x in obj)
    if hasattr(obj, 'n'): # FQ
        return int(obj)
    return obj

def deserialize_g1(data):
    prim = pickle.loads(data)
    # prim is (x, y) ints
    return (FQ(prim[0]), FQ(prim[1]))

def deserialize_g2(data):
    prim = pickle.loads(data)
    # prim is ((x1, x2), (y1, y2))
    x = FQ2(prim[0])
    y = FQ2(prim[1])
    return (x, y)

class ECCIBE(IBEInterface):
    """
    A simulated IBE scheme using Deterministic ECC Key Derivation.
    
    This is NOT a true IBE - it requires fetching identity-specific public key
    before encryption. However, it provides functional equivalence when KMS
    is always available.
    
    Setup: MSK (32 bytes random)
    Extract(ID): sk = SHA256(MSK || ID), pk = sk * G
    Encrypt(pk_ID, M): ECIES(pk_ID, M) -- Requires pk_ID from extract_public()
    Decrypt(sk, C): ECIES(sk, C)
    """
    
    @property
    def scheme_name(self) -> str:
        return "eccibe"
    
    @property
    def is_true_ibe(self) -> bool:
        return False  # Requires extract_public() before encrypt()
    
    def setup(self) -> Tuple[Any, Any]:
        msk = os.urandom(32)
        params = b"ECC-P256-HKDF" # Public params are just algorithm ID in this scheme
        return (params, msk)

    def extract(self, msk: Any, identity: str) -> Any:
        # Derive sk from MSK and ID
        # To match C++ SGX implementation, we use simple SHA256(MSK || FID)
        # instead of HKDF.
        hasher = hashlib.sha256()
        hasher.update(msk)
        hasher.update(identity.encode('utf-8'))
        sk_bytes = hasher.digest()
        
        # Create Private Key Object
        # SGX `sgx_ec256_private_t` uses little-endian scalar representation.
        # Align here so the Python SDK crypto matches enclave derivation.
        sk_int = int.from_bytes(sk_bytes, 'little')
        private_key = ec.derive_private_key(sk_int, ec.SECP256R1(), default_backend())
        # Return Private Key Bytes (DER)
        return private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def extract_public(self, msk: Any, identity: str) -> Any:
        """
        Extract public key for a specific identity.
        Required for ECCIBE since it's not a true IBE.
        """
        sk_bytes = self.extract(msk, identity)
        private_key = serialization.load_der_private_key(
            sk_bytes, password=None, backend=default_backend()
        )
        public_key = private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt(self, params: Any, identity: str, message: bytes) -> bytes:
        # In this scheme, 'params' should ideally contain the Public Key for the ID.
        # But standard IBE Encrypt takes (GlobalParams, ID, Message).
        # Since we can't derive PK from ID without MSK, we assume 'params' *IS* the Public Key for the ID
        # OR we assume the caller has fetched it.
        # For compatibility with the interface, we'll assume 'params' passed here IS the Public Key bytes.
        
        public_key = serialization.load_der_public_key(params, backend=default_backend())
        
        # ECIES Encryption (Ephemeral ECDH + AES-GCM)
        ephemeral_sk = ec.generate_private_key(ec.SECP256R1(), default_backend())
        shared_secret = ephemeral_sk.exchange(ec.ECDH(), public_key)
        # SGX `sgx_ec256_dh_shared_t` uses little-endian bytes; reverse to match enclave derivation.
        shared_secret = shared_secret[::-1]
        
        # Derive AES-128 key.
        # Keep this lightweight and enclave-friendly: AES key = SHA256(SS || "ECC-IBE-ENC")[:16]
        aes_key = hashlib.sha256(shared_secret + b"ECC-IBE-ENC").digest()[:16]
        
        # Encrypt Message
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ct_and_tag = aesgcm.encrypt(nonce, message, None)
        tag = ct_and_tag[-16:]
        ciphertext = ct_and_tag[:-16]
        
        # Pack: EphemeralPub(Uncompressed 65 bytes) + Nonce + Ciphertext
        ephemeral_pk_bytes = ephemeral_sk.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # Format (KeyCiphertextV1 in this repo):
        #   EphemeralPK(65) || Nonce(12) || Tag(16) || Ciphertext
        return ephemeral_pk_bytes + nonce + tag + ciphertext

    def decrypt(self, sk: Any, ciphertext: bytes) -> bytes:
        private_key = serialization.load_der_private_key(
            sk, password=None, backend=default_backend()
        )
        
        # Unpack
        # EphemeralPK is always 65 bytes for P-256 Uncompressed
        if len(ciphertext) < 65 + 12 + 16:
            raise ValueError("Ciphertext too short")
            
        ephemeral_pk_bytes = ciphertext[:65]
        nonce = ciphertext[65:65+12]
        tag = ciphertext[65+12:65+12+16]
        ct = ciphertext[65+12+16:]
        
        ephemeral_pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_pk_bytes)
        
        # ECDH
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_pk)
        # Must match encrypt(): reverse to align with SGX little-endian shared secret bytes.
        shared_secret = shared_secret[::-1]
        
        # Derive AES-128 key (must match encrypt()).
        aes_key = hashlib.sha256(shared_secret + b"ECC-IBE-ENC").digest()[:16]
        
        # Decrypt
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ct + tag, None)

class BonehFranklinIBE(IBEInterface):
    """
    True Boneh-Franklin Identity-Based Encryption using BN128 pairing curve.
    
    This is a TRUE IBE scheme - encryption only requires global public parameters
    and identity string. No need to fetch identity-specific public key.
    
    Based on: "Identity-Based Encryption from the Weil Pairing" (Boneh & Franklin, 2001)
    
    Setup: (P_pub = msk * G2, msk)
    Extract(ID): sk_ID = msk * H(ID)  where H maps to G1
    Encrypt(params, ID, M): Uses pairing e(P_pub, H(ID))^r as session key
    Decrypt(sk_ID, C): Uses pairing e(C1, sk_ID) to recover session key
    
    Security: ~128-bit (BN128 curve)
    Performance: Slower than ECC (~50-100ms per pairing)
    """
    
    @property
    def scheme_name(self) -> str:
        return "boneh-franklin"
    
    @property
    def is_true_ibe(self) -> bool:
        return True  # Can encrypt with just global params and identity
    
    def setup(self) -> Tuple[Any, Any]:
        # msk is a random scalar
        msk = int.from_bytes(os.urandom(32), 'big') % curve_order
        # params is P_pub = msk * G2
        P_pub = multiply(G2, msk)
        return (pickle.dumps(to_primitive(P_pub)), pickle.dumps(msk))

    def extract(self, msk: Any, identity: str) -> Any:
        msk_int = pickle.loads(msk)
        # Map ID to G1
        id_hash = int.from_bytes(hashlib.sha256(identity.encode()).digest(), 'big') % curve_order
        Q_ID = multiply(G1, id_hash)
        # sk_ID = msk * Q_ID
        sk_ID = multiply(Q_ID, msk_int)
        return pickle.dumps(to_primitive(sk_ID))

    def encrypt(self, params: Any, identity: str, message: bytes) -> bytes:
        P_pub = deserialize_g2(params)
        # Map ID to G1
        id_hash = int.from_bytes(hashlib.sha256(identity.encode()).digest(), 'big') % curve_order
        Q_ID = multiply(G1, id_hash)
        
        # r random
        r = int.from_bytes(os.urandom(32), 'big') % curve_order
        
        # C1 = r * G2
        C1 = multiply(G2, r)
        
        # g_id = pair(P_pub, Q_ID)
        g_id = pairing(P_pub, Q_ID)
        
        # session_key_point = g_id ** r
        session_key_point = g_id ** r
        
        # Derive symmetric key from session_key_point
        shared_secret_bytes = pickle.dumps(to_primitive(session_key_point))
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ibe-shared-secret'
        ).derive(shared_secret_bytes)
        
        # Encrypt message with AES-GCM
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ciphertext_payload = aesgcm.encrypt(nonce, message, None)
        
        # Return (C1, nonce, ciphertext_payload)
        return pickle.dumps((to_primitive(C1), nonce, ciphertext_payload))

    def decrypt(self, sk_ID: Any, ciphertext: bytes) -> bytes:
        sk_ID_point = deserialize_g1(sk_ID)
        (C1_prim, nonce, ciphertext_payload) = pickle.loads(ciphertext)
        
        # Reconstruct C1
        C1 = (FQ2(C1_prim[0]), FQ2(C1_prim[1]))
        
        # shared_secret = pair(C1, sk_ID)
        session_key_point = pairing(C1, sk_ID_point)
        
        shared_secret_bytes = pickle.dumps(to_primitive(session_key_point))
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ibe-shared-secret'
        ).derive(shared_secret_bytes)
        
        aesgcm = AESGCM(derived_key)
        return aesgcm.decrypt(nonce, ciphertext_payload, None)
