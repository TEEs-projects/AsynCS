#!/usr/bin/env python3
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _private_key_for_scalar(value: int):
    return ec.derive_private_key(value, ec.SECP256R1())


def _sgx_le_public_key_from_private(private_key) -> bytes:
    be = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return b"\x04" + be[1:33][::-1] + be[33:65][::-1]


def test_sgx_le_public_key_is_converted_to_standard_x962_point() -> None:
    from client_sdk.worker_smoke_artifacts import sgx_le_public_key_to_x962_be

    private_key = _private_key_for_scalar(7)
    expected = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    assert sgx_le_public_key_to_x962_be(_sgx_le_public_key_from_private(private_key)) == expected


def test_key_ciphertext_v1_round_trips_with_existing_eccibe_decrypt() -> None:
    from client_sdk.worker_smoke_artifacts import encrypt_key_ciphertext_v1
    from crypto_lib.ibe import ECCIBE

    private_key = _private_key_for_scalar(11)
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_sgx_le = _sgx_le_public_key_from_private(private_key)
    plaintext = b"k" * 16

    ciphertext = encrypt_key_ciphertext_v1(public_key_sgx_le, plaintext)

    assert len(ciphertext) == 65 + 12 + 16 + len(plaintext)
    assert ciphertext[0] == 0x04
    assert ECCIBE().decrypt(private_der, ciphertext) == plaintext


def test_artifact_plan_uses_protocol_aad_and_rid(tmp_path) -> None:
    from client_sdk.worker_smoke_artifacts import build_artifact_plan

    fid = "01" * 32
    k_func = b"f" * 16
    k_req = b"r" * 16
    pkU = b"\x04" + b"\x02" * 64
    nonce = b"\x03" * 16

    plan = build_artifact_plan(
        fid=fid,
        wasm_bytes=b"\x00asm\x01\x00\x00\x00",
        input_bytes=b"hello",
        k_func=k_func,
        k_req=k_req,
        pkU=pkU,
        nonce=nonce,
    )

    assert plan.label == hashlib.sha256(plan.c_func).hexdigest()
    assert plan.rid == hashlib.sha256(bytes.fromhex(fid) + plan.c_req).hexdigest()
    assert plan.aad_pkg == b"PKG" + bytes.fromhex(fid)
    assert plan.aad_req.startswith(b"REQ" + bytes.fromhex(fid) + nonce)


def test_bfibe_artifacts_use_mcl_tool_with_protocol_identities_and_contexts(tmp_path, monkeypatch) -> None:
    from client_sdk import worker_smoke_artifacts as artifacts
    from crypto_lib.bfibe_envelope import encode_bfibe_envelope, BfIbeEnvelope

    calls = []
    fid = "02" * 32
    wasm_path = tmp_path / "action.wasm"
    wasm_path.write_bytes(b"\x00asm\x01\x00\x00\x00")
    k_func = b"f" * 16
    k_req = b"r" * 16
    nonce = b"\x03" * 16

    monkeypatch.setattr(artifacts, "run_kms_bfibe_public_params", lambda _kms_dir: b"M" * 48)
    monkeypatch.setattr(artifacts, "build_bfibe_mcl_client_tool", lambda: tmp_path / "bfibe-tool")

    def fake_encrypt(*, tool_path, mpk, purpose, identity, aad_context, plaintext, out_path):
        calls.append(
            {
                "tool_path": tool_path,
                "mpk": mpk,
                "purpose": purpose,
                "identity": identity,
                "aad_context": aad_context,
                "plaintext": plaintext,
                "out_path": out_path,
            }
        )
        envelope = encode_bfibe_envelope(
            BfIbeEnvelope(
                purpose=purpose,
                identity=identity,
                aad_context=aad_context,
                c1=b"C" * 48,
                nonce=b"N" * 12,
                ciphertext=b"T" * 32,
            )
        )
        out_path.write_bytes(envelope)
        return envelope

    monkeypatch.setattr(artifacts, "run_bfibe_mcl_client_tool", fake_encrypt)

    built = artifacts.build_worker_smoke_artifacts(
        fid=fid,
        wasm_path=wasm_path,
        input_bytes=b"hello",
        kms_dir=tmp_path,
        out_dir=tmp_path / "out",
        k_func=k_func,
        k_req=k_req,
        nonce=nonce,
        crypto_profile="bfibe",
    )

    assert len(calls) == 2
    function_call, request_call = calls
    assert function_call["purpose"] == "function-key"
    assert function_call["identity"] == f"label:{built.label}"
    assert function_call["aad_context"] == artifacts.build_aad_pkg(fid)
    assert function_call["plaintext"] == k_func
    assert request_call["purpose"] == "request-key"
    assert request_call["identity"] == f"fid:{fid}"
    assert request_call["aad_context"].startswith(b"REQ" + bytes.fromhex(fid) + nonce)
    assert request_call["plaintext"] == k_req
    assert built.c_k_func_path.read_bytes().startswith(b"ASBFIBE1")
    assert built.c_key_path.read_bytes().startswith(b"ASBFIBE1")
    metadata = built.metadata_path.read_text(encoding="utf-8")
    assert '"crypto_profile": "bfibe-mcl-bls12381"' in metadata
    assert '"key_ciphertext_format": "bfibe-mcl-bls12381-envelope-v1"' in metadata
