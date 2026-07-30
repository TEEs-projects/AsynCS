import os
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

from .bfibe_envelope import BFIBE_KEY_CIPHERTEXT_FORMAT, BFIBE_PROFILE_ID


DEFAULT_CRYPTO_PROFILE = "eccibe"
CRYPTO_PROFILE_ENV = "ASYNCS_CRYPTO_PROFILE"


@dataclass(frozen=True)
class CryptoProfile:
    """Protocol-level crypto profile selected by config."""

    profile_id: str
    aliases: Tuple[str, ...]
    python_scheme: Optional[str]
    key_ciphertext_format: str
    is_true_ibe: bool
    sgx_integrated: bool
    description: str

    @property
    def client_sdk_enabled(self) -> bool:
        return self.python_scheme is not None


_CRYPTO_PROFILES = (
    CryptoProfile(
        profile_id="eccibe",
        aliases=("eccibe", "compat", "default", "legacy-eccibe", "eccibe-p256"),
        python_scheme="eccibe",
        key_ciphertext_format="key-ciphertext-v1-ecc-p256",
        is_true_ibe=False,
        sgx_integrated=True,
        description=(
            "Current SGX-integrated compatibility profile. It uses deterministic "
            "P-256 key derivation plus ECIES-style key ciphertexts and requires an "
            "identity-specific public key before client encryption."
        ),
    ),
    CryptoProfile(
        profile_id=BFIBE_PROFILE_ID,
        aliases=(
            "bfibe",
            "bfibe-mcl",
            "bfibe-mcl-bls12381",
            "mcl-bfibe",
            "mcl-bls12381",
            "boneh-franklin-mcl",
        ),
        python_scheme=None,
        key_ciphertext_format=BFIBE_KEY_CIPHERTEXT_FORMAT,
        is_true_ibe=True,
        sgx_integrated=False,
        description=(
            "Target true IBE profile for the SGX/MCL BLS12-381 integration. "
            "It is registered so config and metadata can name the paper-target "
            "profile, but it must not silently fall back to the older Python demo."
        ),
    ),
    CryptoProfile(
        profile_id="bfibe-py-ecc-bn128-demo",
        aliases=(
            "boneh-franklin",
            "bfibe-demo",
            "bfibe-py-ecc-bn128-demo",
            "py-ecc-bn128",
        ),
        python_scheme="boneh-franklin",
        key_ciphertext_format="py-ecc-bn128-pickle-demo",
        is_true_ibe=True,
        sgx_integrated=False,
        description=(
            "Python-only Boneh-Franklin demonstration profile. It uses py_ecc BN128 "
            "and pickle serialization, so it is not the SGX/MCL BLS12-381 profile "
            "and must not be used as measured AsynCS implementation evidence."
        ),
    ),
)


def _normalise_name(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def list_crypto_profiles() -> Tuple[CryptoProfile, ...]:
    return _CRYPTO_PROFILES


def _all_profile_names(profile: CryptoProfile) -> Iterable[str]:
    yield profile.profile_id
    yield from profile.aliases


def get_crypto_profile(name: Optional[str] = None, env=os.environ) -> CryptoProfile:
    requested = name
    if requested is None or str(requested).strip() == "":
        requested = env.get(CRYPTO_PROFILE_ENV, DEFAULT_CRYPTO_PROFILE)

    wanted = _normalise_name(str(requested))
    for profile in _CRYPTO_PROFILES:
        if wanted in {_normalise_name(item) for item in _all_profile_names(profile)}:
            return profile

    available = ", ".join(profile.profile_id for profile in _CRYPTO_PROFILES)
    raise ValueError(f"Unknown crypto profile: {requested}. Available profiles: {available}")
