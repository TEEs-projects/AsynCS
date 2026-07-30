"""Public crypto helpers with lightweight package import boundaries.

Profile-only users, such as the OpenWhisk runtime proxy, must not need optional
Python demo dependencies like ``py_ecc``. Heavy primitives stay available via
lazy package attributes and are imported only when requested.
"""

from importlib import import_module

from .bfibe_key_release import (
    BfIbeKeyRelease,
    BfIbePrivateKeyRecord,
    BfIbePrivateKeySet,
    decode_bfibe_key_release,
    decode_bfibe_private_key_set,
    encode_bfibe_key_release,
    encode_bfibe_private_key_set,
    key_release_associated_data,
)
from .interfaces import AEADInterface, HashInterface, IBEInterface, KEMInterface
from .profiles import get_crypto_profile, list_crypto_profiles


_LAZY_EXPORTS = {
    "AESGCMImpl": (".aead", "AESGCMImpl"),
    "ChaCha20Poly1305Impl": (".aead", "ChaCha20Poly1305Impl"),
    "X25519HKDFKEM": (".kem", "X25519HKDFKEM"),
    "P256HKDFKEM": (".kem", "P256HKDFKEM"),
    "ECCIBE": (".ibe", "ECCIBE"),
    "BonehFranklinIBE": (".ibe", "BonehFranklinIBE"),
    "SHA256Impl": (".hash", "SHA256Impl"),
    "SHA384Impl": (".hash", "SHA384Impl"),
}

_EXTRA_IBE_SCHEMES = {}


def __getattr__(name):
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = _LAZY_EXPORTS[name]
    value = getattr(import_module(module_name, __name__), attr_name)
    globals()[name] = value
    return value


def _built_in_ibe_schemes():
    return {
        "eccibe": __getattr__("ECCIBE"),
        "boneh-franklin": __getattr__("BonehFranklinIBE"),
    }


def get_ibe_scheme(scheme_name: str) -> IBEInterface:
    """
    Factory function to get an IBE scheme by name.

    Args:
        scheme_name: Name of the scheme, for example ``eccibe``.

    Returns:
        An instance of the requested scheme.

    Raises:
        ValueError: If ``scheme_name`` is not recognized.
    """
    normalised = scheme_name.lower()
    schemes = _built_in_ibe_schemes()
    schemes.update(_EXTRA_IBE_SCHEMES)
    if normalised not in schemes:
        available = ", ".join(sorted(schemes))
        raise ValueError(f"Unknown IBE scheme: {scheme_name}. Available: {available}")
    return schemes[normalised]()


def list_ibe_schemes() -> list:
    """Return registered IBE scheme names."""
    return sorted({*("eccibe", "boneh-franklin"), *_EXTRA_IBE_SCHEMES.keys()})


def register_ibe_scheme(name: str, scheme_class: type):
    """
    Register a new IBE scheme.

    Args:
        name: Name to register the scheme under.
        scheme_class: Class implementing ``IBEInterface``.
    """
    if not issubclass(scheme_class, IBEInterface):
        raise TypeError(f"{scheme_class} must implement IBEInterface")
    _EXTRA_IBE_SCHEMES[name.lower()] = scheme_class


__all__ = [
    "AEADInterface",
    "KEMInterface",
    "IBEInterface",
    "HashInterface",
    "AESGCMImpl",
    "ChaCha20Poly1305Impl",
    "X25519HKDFKEM",
    "P256HKDFKEM",
    "ECCIBE",
    "BonehFranklinIBE",
    "SHA256Impl",
    "SHA384Impl",
    "get_crypto_profile",
    "list_crypto_profiles",
    "get_ibe_scheme",
    "list_ibe_schemes",
    "register_ibe_scheme",
    "BfIbeKeyRelease",
    "BfIbePrivateKeyRecord",
    "BfIbePrivateKeySet",
    "decode_bfibe_key_release",
    "decode_bfibe_private_key_set",
    "encode_bfibe_key_release",
    "encode_bfibe_private_key_set",
    "key_release_associated_data",
]
