import struct
from dataclasses import dataclass
from typing import Tuple

from .bfibe_envelope import BFIBE_PROFILE_ID


BFIBE_PRIVATE_KEY_SET_MAGIC = b"ASBFSKS1"
BFIBE_PRIVATE_KEY_SET_VERSION = 1
BFIBE_KEY_RELEASE_MAGIC = b"ASBFREL1"
BFIBE_KEY_RELEASE_VERSION = 1

_ALLOWED_PURPOSES = frozenset(("function-key", "request-key"))
_PRIVATE_KEY_SET_HEADER = struct.Struct(">8sBII")
_RECORD_HEADER = struct.Struct(">III")
_KEY_RELEASE_HEADER = struct.Struct(">8sBIIIIII")
_AAD_MAGIC = b"ASYNCS/BFIBE/KEYRELEASE/AAD/v1"


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
class BfIbePrivateKeyRecord:
    purpose: str
    identity: str
    private_key: bytes

    def __post_init__(self) -> None:
        if self.purpose not in _ALLOWED_PURPOSES:
            allowed = ", ".join(sorted(_ALLOWED_PURPOSES))
            raise ValueError(f"Unsupported BF-IBE key-release purpose: {self.purpose}. Allowed: {allowed}")
        _encode_text("identity", self.identity)
        _require_bytes("private_key", self.private_key)
        if len(self.private_key) == 0:
            raise ValueError("private_key must not be empty")


@dataclass(frozen=True)
class BfIbePrivateKeySet:
    records: Tuple[BfIbePrivateKeyRecord, ...]
    profile_id: str = BFIBE_PROFILE_ID

    def __post_init__(self) -> None:
        if self.profile_id != BFIBE_PROFILE_ID:
            raise ValueError(f"Unsupported BF-IBE profile: {self.profile_id}")
        if not isinstance(self.records, tuple):
            object.__setattr__(self, "records", tuple(self.records))
        if len(self.records) == 0:
            raise ValueError("records must not be empty")
        for record in self.records:
            if not isinstance(record, BfIbePrivateKeyRecord):
                raise TypeError("records must contain BfIbePrivateKeyRecord values")


@dataclass(frozen=True)
class BfIbeKeyRelease:
    fid: str
    worker_identity: str
    wrap_public_key: bytes
    nonce: bytes
    ciphertext: bytes
    profile_id: str = BFIBE_PROFILE_ID

    def __post_init__(self) -> None:
        if self.profile_id != BFIBE_PROFILE_ID:
            raise ValueError(f"Unsupported BF-IBE profile: {self.profile_id}")
        _encode_text("fid", self.fid)
        _encode_text("worker_identity", self.worker_identity)
        _require_bytes("wrap_public_key", self.wrap_public_key)
        _require_bytes("nonce", self.nonce)
        _require_bytes("ciphertext", self.ciphertext)
        if len(self.wrap_public_key) == 0:
            raise ValueError("wrap_public_key must not be empty")
        if len(self.nonce) != 12:
            raise ValueError("nonce must be 12 bytes for AES-GCM")
        if len(self.ciphertext) == 0:
            raise ValueError("ciphertext must not be empty")


def encode_bfibe_private_key_set(key_set: BfIbePrivateKeySet) -> bytes:
    profile = _encode_text("profile_id", key_set.profile_id)
    encoded_records = []
    for record in key_set.records:
        purpose = _encode_text("purpose", record.purpose)
        identity = _encode_text("identity", record.identity)
        private_key = record.private_key
        encoded_records.append(
            _RECORD_HEADER.pack(len(purpose), len(identity), len(private_key))
            + purpose
            + identity
            + private_key
        )

    header = _PRIVATE_KEY_SET_HEADER.pack(
        BFIBE_PRIVATE_KEY_SET_MAGIC,
        BFIBE_PRIVATE_KEY_SET_VERSION,
        len(profile),
        len(encoded_records),
    )
    return header + profile + b"".join(encoded_records)


def decode_bfibe_private_key_set(data: bytes) -> BfIbePrivateKeySet:
    _require_bytes("data", data)
    if len(data) < _PRIVATE_KEY_SET_HEADER.size:
        raise ValueError("BF-IBE private-key set is shorter than the fixed header")

    magic, version, profile_len, record_count = _PRIVATE_KEY_SET_HEADER.unpack(
        data[: _PRIVATE_KEY_SET_HEADER.size]
    )
    if magic != BFIBE_PRIVATE_KEY_SET_MAGIC:
        raise ValueError("Invalid BF-IBE private-key set magic")
    if version != BFIBE_PRIVATE_KEY_SET_VERSION:
        raise ValueError(f"Unsupported BF-IBE private-key set version: {version}")
    if record_count == 0:
        raise ValueError("BF-IBE private-key set records must not be empty")

    offset = _PRIVATE_KEY_SET_HEADER.size

    def take(length: int) -> bytes:
        nonlocal offset
        if offset + length > len(data):
            raise ValueError("Invalid BF-IBE private-key set length")
        chunk = data[offset : offset + length]
        offset += length
        return chunk

    profile = take(profile_len).decode("utf-8")
    records = []
    for _ in range(record_count):
        if offset + _RECORD_HEADER.size > len(data):
            raise ValueError("Invalid BF-IBE private-key set record length")
        purpose_len, identity_len, private_key_len = _RECORD_HEADER.unpack(
            data[offset : offset + _RECORD_HEADER.size]
        )
        offset += _RECORD_HEADER.size
        purpose = take(purpose_len).decode("utf-8")
        identity = take(identity_len).decode("utf-8")
        private_key = take(private_key_len)
        records.append(
            BfIbePrivateKeyRecord(
                purpose=purpose,
                identity=identity,
                private_key=private_key,
            )
        )

    if offset != len(data):
        raise ValueError(
            f"Invalid BF-IBE private-key set length: expected {offset}, got {len(data)}"
        )

    return BfIbePrivateKeySet(profile_id=profile, records=tuple(records))


def encode_bfibe_key_release(release: BfIbeKeyRelease) -> bytes:
    profile = _encode_text("profile_id", release.profile_id)
    fid = _encode_text("fid", release.fid)
    worker_identity = _encode_text("worker_identity", release.worker_identity)
    wrap_public_key = release.wrap_public_key

    header = _KEY_RELEASE_HEADER.pack(
        BFIBE_KEY_RELEASE_MAGIC,
        BFIBE_KEY_RELEASE_VERSION,
        len(profile),
        len(fid),
        len(worker_identity),
        len(wrap_public_key),
        len(release.nonce),
        len(release.ciphertext),
    )
    return header + profile + fid + worker_identity + wrap_public_key + release.nonce + release.ciphertext


def decode_bfibe_key_release(data: bytes) -> BfIbeKeyRelease:
    _require_bytes("data", data)
    if len(data) < _KEY_RELEASE_HEADER.size:
        raise ValueError("BF-IBE key-release envelope is shorter than the fixed header")

    (
        magic,
        version,
        profile_len,
        fid_len,
        worker_identity_len,
        wrap_public_key_len,
        nonce_len,
        ciphertext_len,
    ) = _KEY_RELEASE_HEADER.unpack(data[: _KEY_RELEASE_HEADER.size])

    if magic != BFIBE_KEY_RELEASE_MAGIC:
        raise ValueError("Invalid BF-IBE key-release magic")
    if version != BFIBE_KEY_RELEASE_VERSION:
        raise ValueError(f"Unsupported BF-IBE key-release version: {version}")

    expected_len = (
        _KEY_RELEASE_HEADER.size
        + profile_len
        + fid_len
        + worker_identity_len
        + wrap_public_key_len
        + nonce_len
        + ciphertext_len
    )
    if len(data) != expected_len:
        raise ValueError(
            f"Invalid BF-IBE key-release length: expected {expected_len}, got {len(data)}"
        )

    offset = _KEY_RELEASE_HEADER.size

    def take(length: int) -> bytes:
        nonlocal offset
        chunk = data[offset : offset + length]
        offset += length
        return chunk

    profile = take(profile_len).decode("utf-8")
    fid = take(fid_len).decode("utf-8")
    worker_identity = take(worker_identity_len).decode("utf-8")
    wrap_public_key = take(wrap_public_key_len)
    nonce = take(nonce_len)
    ciphertext = take(ciphertext_len)

    return BfIbeKeyRelease(
        profile_id=profile,
        fid=fid,
        worker_identity=worker_identity,
        wrap_public_key=wrap_public_key,
        nonce=nonce,
        ciphertext=ciphertext,
    )


def key_release_associated_data(release: BfIbeKeyRelease) -> bytes:
    return (
        _AAD_MAGIC
        + _pack_part(_encode_text("profile_id", release.profile_id))
        + _pack_part(_encode_text("fid", release.fid))
        + _pack_part(_encode_text("worker_identity", release.worker_identity))
        + _pack_part(release.wrap_public_key)
    )
