from abc import ABC, abstractmethod
from typing import Tuple, Any

class AEADInterface(ABC):
    @abstractmethod
    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """
        Encrypts plaintext using the given key and associated data.
        Returns ciphertext.
        """
        pass

    @abstractmethod
    def decrypt(self, key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """
        Decrypts ciphertext using the given key and associated data.
        Returns plaintext.
        """
        pass

class KEMInterface(ABC):
    @abstractmethod
    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generates a public/private key pair.
        Returns (pk, sk).
        """
        pass

    @abstractmethod
    def encap(self, pk: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulates a shared secret for the given public key.
        Returns (ciphertext, shared_secret).
        """
        pass

    @abstractmethod
    def decap(self, sk: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulates the shared secret using the private key.
        Returns shared_secret.
        """
        pass

class IBEInterface(ABC):
    """
    Abstract interface for Identity-Based Encryption (IBE) schemes.
    
    Two types of IBE implementations are supported:
    
    1. True IBE (e.g., Boneh-Franklin):
       - encrypt() only needs global params and identity string
       - No need to fetch public key before encryption
       - Supports "encrypt-before-register" pattern
    
    2. Simulated IBE (e.g., ECCIBE):
       - encrypt() requires identity-specific public key
       - Must call extract_public() or contact KMS first
       - Functionally equivalent when KMS is always available
    
    All implementations must satisfy the identity-based property:
    - Same identity always derives same key
    - Different identities derive different keys
    """
    
    @property
    @abstractmethod
    def scheme_name(self) -> str:
        """Returns the name of the IBE scheme (e.g., 'eccibe', 'boneh-franklin')."""
        pass
    
    @property
    @abstractmethod
    def is_true_ibe(self) -> bool:
        """
        Returns True if this is a true IBE scheme that can encrypt
        without fetching identity-specific public key first.
        """
        pass

    @abstractmethod
    def setup(self) -> Tuple[Any, Any]:
        """
        Generates master public parameters and master secret key.
        Returns (params, msk).
        
        For true IBE: params can be used directly for encryption.
        For simulated IBE: params may just be algorithm identifier.
        """
        pass

    @abstractmethod
    def extract(self, msk: Any, identity: str) -> Any:
        """
        Extracts a user secret key for the given identity.
        Returns sk_ID.
        
        This is called by KMS to derive identity-specific private key.
        """
        pass

    @abstractmethod
    def encrypt(self, params: Any, identity: str, message: bytes) -> bytes:
        """
        Encrypts a message for the given identity.
        Returns ciphertext.
        
        For true IBE: params is global public parameters.
        For simulated IBE: params is the identity-specific public key (pk_ID).
        """
        pass

    @abstractmethod
    def decrypt(self, sk_ID: Any, ciphertext: bytes) -> bytes:
        """
        Decrypts a ciphertext using the user secret key.
        Returns plaintext.
        """
        pass
    
    def extract_public(self, msk: Any, identity: str) -> Any:
        """
        Optional: Extract public key for a specific identity.
        
        For true IBE: Not needed, returns global params.
        For simulated IBE: Returns identity-specific public key.
        
        Default implementation raises NotImplementedError.
        Simulated IBE schemes should override this method.
        """
        raise NotImplementedError(
            f"{self.scheme_name} does not support extract_public. "
            "Use global params for encryption instead."
        )

class HashInterface(ABC):
    @abstractmethod
    def digest(self, data: bytes) -> bytes:
        """
        Computes the hash digest of the data.
        Returns digest bytes.
        """
        pass
