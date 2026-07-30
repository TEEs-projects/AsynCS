import struct
from dataclasses import dataclass


BFIBE_ENVELOPE_MAGIC = b"ASBFIBE1"
BFIBE_ENVELOPE_VERSION = 1
BFIBE_PROFILE_ID = "bfibe-mcl-bls12381"
BFIBE_KEY_CIPHERTEXT_FORMAT = "bfibe-mcl-bls12381-envelope-v1"

_ALLOWED_PURPOSES = frozenset(("function-key", "request-key"))
_HEADER = struct.Struct(">8sBIIIIIII")
_AAD_MAGIC = b"ASYNCS/BFIBE/AAD/v1"


def _require_bytes(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def _encode_text(name: str, value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if value == "":
        raise ValueError(f"{name} must not be empty")
    return value.encode("utf-8")


def _pack_part(part: bytes) -> bytes:
    return struct.pack(">I", len(part)) + part


@dataclass(frozen=True)
class BfIbeEnvelope:
    purpose: str
    identity: str
    aad_context: bytes
    c1: bytes
    nonce: bytes
    ciphertext: bytes
    profile_id: str = BFIBE_PROFILE_ID

    def __post_init__(self) -> None:
        if self.profile_id != BFIBE_PROFILE_ID:
            raise ValueError(f"Unsupported BF-IBE profile: {self.profile_id}")
        if self.purpose not in _ALLOWED_PURPOSES:
            allowed = ", ".join(sorted(_ALLOWED_PURPOSES))
            raise ValueError(f"Unsupported BF-IBE purpose: {self.purpose}. Allowed: {allowed}")
        _encode_text("identity", self.identity)
        _require_bytes("aad_context", self.aad_context)
        _require_bytes("c1", self.c1)
        _require_bytes("nonce", self.nonce)
        _require_bytes("ciphertext", self.ciphertext)
        if len(self.c1) == 0:
            raise ValueError("c1 must not be empty")
        if len(self.nonce) != 12:
            raise ValueError("nonce must be 12 bytes for AES-GCM")
        if len(self.ciphertext) == 0:
            raise ValueError("ciphertext must not be empty")


def encode_bfibe_envelope(envelope: BfIbeEnvelope) -> bytes:
    profile = _encode_text("profile_id", envelope.profile_id)
    purpose = _encode_text("purpose", envelope.purpose)
    identity = _encode_text("identity", envelope.identity)
    aad_context = envelope.aad_context
    c1 = envelope.c1
    nonce = envelope.nonce
    ciphertext = envelope.ciphertext

    header = _HEADER.pack(
        BFIBE_ENVELOPE_MAGIC,
        BFIBE_ENVELOPE_VERSION,
        len(profile),
        len(purpose),
        len(identity),
        len(aad_context),
        len(c1),
        len(nonce),
        len(ciphertext),
    )
    return header + profile + purpose + identity + aad_context + c1 + nonce + ciphertext


def decode_bfibe_envelope(data: bytes) -> BfIbeEnvelope:
    _require_bytes("data", data)
    if len(data) < _HEADER.size:
        raise ValueError("BF-IBE envelope is shorter than the fixed header")

    (
        magic,
        version,
        profile_len,
        purpose_len,
        identity_len,
        aad_context_len,
        c1_len,
        nonce_len,
        ciphertext_len,
    ) = _HEADER.unpack(data[: _HEADER.size])

    if magic != BFIBE_ENVELOPE_MAGIC:
        raise ValueError("Invalid BF-IBE envelope magic")
    if version != BFIBE_ENVELOPE_VERSION:
        raise ValueError(f"Unsupported BF-IBE envelope version: {version}")

    lengths = (
        profile_len,
        purpose_len,
        identity_len,
        aad_context_len,
        c1_len,
        nonce_len,
        ciphertext_len,
    )
    expected_len = _HEADER.size + sum(lengths)
    if len(data) != expected_len:
        raise ValueError(
            f"Invalid BF-IBE envelope length: expected {expected_len}, got {len(data)}"
        )

    offset = _HEADER.size

    def take(length: int) -> bytes:
        nonlocal offset
        chunk = data[offset : offset + length]
        offset += length
        return chunk

    profile = take(profile_len).decode("utf-8")
    purpose = take(purpose_len).decode("utf-8")
    identity = take(identity_len).decode("utf-8")
    aad_context = take(aad_context_len)
    c1 = take(c1_len)
    nonce = take(nonce_len)
    ciphertext = take(ciphertext_len)

    return BfIbeEnvelope(
        profile_id=profile,
        purpose=purpose,
        identity=identity,
        aad_context=aad_context,
        c1=c1,
        nonce=nonce,
        ciphertext=ciphertext,
    )


def envelope_associated_data(envelope: BfIbeEnvelope) -> bytes:
    profile = _encode_text("profile_id", envelope.profile_id)
    purpose = _encode_text("purpose", envelope.purpose)
    identity = _encode_text("identity", envelope.identity)
    return (
        _AAD_MAGIC
        + _pack_part(profile)
        + _pack_part(purpose)
        + _pack_part(identity)
        + _pack_part(envelope.aad_context)
    )
