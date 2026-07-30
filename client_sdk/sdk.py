import hashlib
import os
from typing import Tuple, Optional, Dict, Any
import sys

# Add root to path to import crypto_lib
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_lib.interfaces import AEADInterface, KEMInterface, IBEInterface
from crypto_lib.aead import AESGCMImpl
from crypto_lib.kem import P256HKDFKEM
from crypto_lib import get_ibe_scheme, list_ibe_schemes
from crypto_lib.profiles import get_crypto_profile, list_crypto_profiles, CryptoProfile

class ClientSDK:
    """
    Client SDK for Confidential Serverless Computing.
    
    Supports pluggable crypto profiles. Default is 'eccibe' for backward
    compatibility. Use set_crypto_profile() for the protocol profile boundary;
    set_ibe_scheme() remains as a compatibility alias for older scripts.
    """
    
    def __init__(self, ibe_scheme: Optional[str] = None, *, crypto_profile: Optional[str] = None):
        """
        Initialize the SDK with specified crypto profile.
        
        Args:
            ibe_scheme: Backward-compatible profile/scheme name.
            crypto_profile: Preferred profile name. Examples: 'eccibe',
                'bfibe' or 'boneh-franklin'.
        """
        if ibe_scheme is not None and crypto_profile is not None:
            raise ValueError("Specify either ibe_scheme or crypto_profile, not both")
        self.aead = AESGCMImpl()
        self.kem = P256HKDFKEM()
        self.crypto_profile = self._load_crypto_profile(
            crypto_profile if crypto_profile is not None else ibe_scheme
        )
        self._ibe_scheme_name = self.crypto_profile.python_scheme
        self.ibe = get_ibe_scheme(self._ibe_scheme_name)

    @staticmethod
    def _load_crypto_profile(profile_name: Optional[str]) -> CryptoProfile:
        profile = get_crypto_profile(profile_name)
        if not profile.client_sdk_enabled:
            raise NotImplementedError(
                f"Crypto profile {profile.profile_id} targets MCL/BLS12-381 SGX IBE, "
                "but the KMS/worker/client backend is not integrated yet. "
                "Use crypto_profile='eccibe' for the current implementation or "
                "crypto_profile='boneh-franklin' only for the Python demo."
            )
        return profile

    @property
    def crypto_profile_id(self) -> str:
        """Returns the selected protocol-level crypto profile."""
        return self.crypto_profile.profile_id
    
    @property
    def ibe_scheme_name(self) -> str:
        """Returns the name of the current IBE scheme."""
        return self._ibe_scheme_name
    
    @property
    def is_true_ibe(self) -> bool:
        """Returns True if current IBE scheme is a true IBE (no pk fetch needed)."""
        return self.ibe.is_true_ibe
    
    def set_crypto_profile(self, profile_name: str):
        """
        Switch to a different crypto profile.
        
        Args:
            profile_name: Name or alias of the crypto profile to use.
        """
        self.crypto_profile = self._load_crypto_profile(profile_name)
        self._ibe_scheme_name = self.crypto_profile.python_scheme
        self.ibe = get_ibe_scheme(self._ibe_scheme_name)

    def set_ibe_scheme(self, scheme_name: str):
        """
        Backward-compatible alias for set_crypto_profile().
        """
        self.set_crypto_profile(scheme_name)
    
    @staticmethod
    def available_ibe_schemes() -> list:
        """Returns list of available IBE scheme names."""
        return list_ibe_schemes()

    @staticmethod
    def available_crypto_profiles() -> list:
        """Returns list of available protocol-level crypto profile IDs."""
        return [profile.profile_id for profile in list_crypto_profiles()]

    def _hash(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def compute_fid(self, tenant_id: str, action_name: str, version: str, code_wasm: bytes) -> str:
        """
        Computes the Function ID (FID).
        FID = H(tenant_id || action_name || version || func_measurement)
        func_measurement = H(code_wasm)
        """
        func_measurement = self._hash(code_wasm)
        
        # Concatenate inputs. Using a separator to avoid collision attacks is good practice, 
        # but spec says "||" which usually implies simple concatenation. 
        # I will use simple concatenation as per spec, but ensure types are bytes.
        
        raw_data = (
            tenant_id.encode('utf-8') + 
            action_name.encode('utf-8') + 
            version.encode('utf-8') + 
            func_measurement
        )
        
        fid_bytes = self._hash(raw_data)
        return fid_bytes.hex()

    def _build_aad_pkg(self, fid: str) -> bytes:
        """
        Construct aad_pkg = ("PKG", FID) for function code encryption.
        This ensures the ciphertext is bound to the package context and specific FID.
        """
        fid_bytes = bytes.fromhex(fid)
        # Format: "PKG" prefix (3 bytes) + FID (32 bytes)
        return b"PKG" + fid_bytes

    def encrypt_function_code(self, tenant_id: str, action_name: str, version: str, code_wasm: bytes) -> dict:
        """
        Step 1 of Deployment:
        1. Compute FID
        2. Generate k_func
        3. Encrypt code -> C_func with aad_pkg=("PKG",FID)
        4. Compute L = H(C_func)
        Returns: {fid, c_func, l, k_func, func_measurement}
        """
        fid = self.compute_fid(tenant_id, action_name, version, code_wasm)
        
        # Generate k_func (AES-GCM key is 16 bytes for 128-bit)
        k_func = os.urandom(16)
        
        # Encrypt code with proper AAD binding
        # C_func = AEAD.Enc(k_func, code_wasm, aad_pkg=("PKG",FID))
        aad_pkg = self._build_aad_pkg(fid)
        c_func = self.aead.encrypt(k_func, code_wasm, aad_pkg)
        
        # Compute L = H(C_func)
        l_bytes = self._hash(c_func)
        l_hex = l_bytes.hex()
        
        return {
            "fid": fid,
            "c_func": c_func,
            "l": l_hex,
            "k_func": k_func,
            "func_measurement": self._hash(code_wasm).hex(),
            "crypto_profile": self.crypto_profile.profile_id,
        }

    def encrypt_function_key(self, k_func: bytes, pk_L: bytes, l_hex: str) -> bytes:
        """
        Step 2 of Deployment:
        Encrypt k_func using IBE (pk_L).
        Returns: c_k_func
        """
        return self.ibe.encrypt(pk_L, l_hex, k_func)

    def _build_aad_req(self, fid: str, nonce: str, pkU: bytes) -> bytes:
        """
        Construct aad_req = ("REQ", FID, nonce, H(pkU)) for request encryption.
        This ensures the ciphertext is bound to the request context, FID, nonce, and user's public key.
        """
        fid_bytes = bytes.fromhex(fid)
        nonce_bytes = bytes.fromhex(nonce)
        h_pkU = self._hash(pkU)
        # Format: "REQ" prefix (3 bytes) + FID (32 bytes) + nonce (16 bytes) + H(pkU) (32 bytes)
        return b"REQ" + fid_bytes + nonce_bytes + h_pkU

    def _compute_rid(self, fid: str, c_req: bytes) -> str:
        """
        Compute RID = H(FID || C_req).
        RID is a deterministic identifier for the request that both client and worker can compute.
        """
        fid_bytes = bytes.fromhex(fid)
        rid_bytes = self._hash(fid_bytes + c_req)
        return rid_bytes.hex()

    def prepare_invocation(self, fid: str, input_data: bytes, pk_FID: bytes) -> dict:
        """
        Prepares the invocation.
        1. Generate k_req
        2. Generate KEM keypair (pkU, skU)
        3. Generate nonce
        4. Encrypt input -> C_req with aad_req=("REQ",FID,nonce,H(pkU))
        5. Encrypt k_req -> C_key (using IBE with ID=FID and pk_FID)
        6. Compute RID = H(FID || C_req)
        Returns: {fid, c_req, c_key, pkU, skU, nonce, rid, ibe_scheme}
        """
        # 1. Generate k_req
        k_req = os.urandom(16)
        
        # 2. Generate KEM keypair first (needed for AAD)
        # (pkU, skU) = KEM.KeyGen()
        pkU, skU = self.kem.keygen()
        
        # 3. Generate nonce first (needed for AAD)
        nonce = os.urandom(16).hex()
        
        # 4. Encrypt input -> C_req with proper AAD binding
        # C_req = AEAD.Enc(k_req, input, aad_req=("REQ",FID,nonce,H(pkU)))
        aad_req = self._build_aad_req(fid, nonce, pkU)
        c_req = self.aead.encrypt(k_req, input_data, aad_req)
        
        # 5. Encrypt k_req -> C_key
        # C_key = IBE.Enc(pk_FID, ID=FID, M=k_req)
        c_key = self.ibe.encrypt(pk_FID, fid, k_req)
        
        # 6. Compute RID = H(FID || C_req)
        rid = self._compute_rid(fid, c_req)
        
        return {
            "fid": fid,
            "c_req": c_req,
            "c_key": c_key,
            "pkU": pkU,
            "skU": skU,
            "nonce": nonce,
            "rid": rid,
            "ibe_scheme": self._ibe_scheme_name,
            "crypto_profile": self.crypto_profile.profile_id,
            "key_ciphertext_format": self.crypto_profile.key_ciphertext_format,
        }

    def _build_aad_out(self, fid: str, rid: str, pkU: bytes) -> bytes:
        """
        Construct aad_out = ("OUT", FID, RID, H(pkU)) for output decryption.
        This ensures the ciphertext is bound to the output context, FID, RID, and user's public key.
        AID is explicitly NOT used in AAD as it is untrusted metadata.
        """
        fid_bytes = bytes.fromhex(fid)
        rid_bytes = bytes.fromhex(rid)
        h_pkU = self._hash(pkU)
        # Format: "OUT" prefix (3 bytes) + FID (32 bytes) + RID (32 bytes) + H(pkU) (32 bytes)
        return b"OUT" + fid_bytes + rid_bytes + h_pkU

    def decrypt_result(self, ct: bytes, c_out: bytes, skU: bytes, fid: str, rid: str, pkU: bytes) -> bytes:
        """
        Decrypts the result using the new protocol binding.
        1. k_U = KEM.Decap(skU, ct)
        2. output = AEAD.Dec(k_U, C_out, aad_out=("OUT",FID,RID,H(pkU)))
        
        Note: AID is NOT used for AAD as it is untrusted metadata.
        The binding is to FID, RID (computed from request), and the user's public key.
        
        Args:
            ct: KEM ciphertext from worker
            c_out: AEAD encrypted output from worker
            skU: User's KEM secret key
            fid: Function ID
            rid: Request ID = H(FID || C_req)
            pkU: User's KEM public key
            
        Returns:
            Decrypted output bytes
        """
        # 1. k_U = KEM.Decap(skU, ct)
        k_U = self.kem.decap(skU, ct)
        # SGX worker uses AES-128-GCM (sgx_rijndael128GCM) with the first 16 bytes.
        k_U_128 = k_U[:16]
        
        # 2. output = AEAD.Dec(k_U, C_out, aad_out=("OUT",FID,RID,H(pkU)))
        aad_out = self._build_aad_out(fid, rid, pkU)
        output = self.aead.decrypt(k_U_128, c_out, aad_out)
        
        return output
    
    def decrypt_result_legacy(self, ct: bytes, c_out: bytes, skU: bytes, aid: str) -> bytes:
        """
        Legacy decryption method for backward compatibility.
        Uses AID as AAD (deprecated, kept for migration purposes only).
        
        WARNING: This method is deprecated and will be removed in a future version.
        Use decrypt_result() with proper (fid, rid, pkU) parameters instead.
        """
        # 1. k_U = KEM.Decap(skU, ct)
        k_U = self.kem.decap(skU, ct)
        
        # 2. output = AEAD.Dec(k_U, C_out, aad=AID) [DEPRECATED]
        aid_bytes = aid.encode('utf-8')
        output = self.aead.decrypt(k_U, c_out, aid_bytes)
        
        return output
    
    def get_scheme_info(self) -> Dict[str, Any]:
        """
        Returns information about the current cryptographic configuration.
        """
        return {
            "crypto_profile": self.crypto_profile.profile_id,
            "ibe_scheme": self._ibe_scheme_name,
            "is_true_ibe": self.ibe.is_true_ibe,
            "sgx_integrated": self.crypto_profile.sgx_integrated,
            "key_ciphertext_format": self.crypto_profile.key_ciphertext_format,
            "aead": "AES-GCM-128",
            "kem": "P256-HKDF",
            "hash": "SHA-256",
            "available_ibe_schemes": list_ibe_schemes(),
            "available_crypto_profiles": self.available_crypto_profiles(),
        }
