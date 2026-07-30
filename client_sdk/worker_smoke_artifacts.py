#!/usr/bin/env python3
"""Build protocol-compatible artifacts for local SGX worker smoke tests."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_lib.aead import AESGCMImpl
from crypto_lib.kem import P256HKDFKEM
from crypto_lib.profiles import get_crypto_profile


ACSC_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ArtifactPlan:
    fid: str
    label: str
    rid: str
    aad_pkg: bytes
    aad_req: bytes
    c_func: bytes
    c_req: bytes


@dataclass(frozen=True)
class WorkerSmokeArtifacts:
    fid: str
    label: str
    rid: str
    c_func_path: Path
    c_req_path: Path
    c_k_func_path: Path
    c_key_path: Path
    pku_path: Path
    sku_path: Path
    nonce_path: Path
    metadata_path: Path


def fid_bytes(fid: str) -> bytes:
    stripped = (fid or "").strip()
    if len(stripped) == 64:
        try:
            return bytes.fromhex(stripped)
        except ValueError:
            pass
    return stripped.encode("utf-8")


def build_aad_pkg(fid: str) -> bytes:
    return b"PKG" + fid_bytes(fid)


def build_aad_req(fid: str, nonce: bytes, pkU: bytes) -> bytes:
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    return b"REQ" + fid_bytes(fid) + nonce + hashlib.sha256(pkU).digest()


def compute_rid(fid: str, c_req: bytes) -> str:
    return hashlib.sha256(fid_bytes(fid) + c_req).hexdigest()


def sgx_le_public_key_to_x962_be(public_key_sgx_le: bytes) -> bytes:
    if len(public_key_sgx_le) != 65 or public_key_sgx_le[0] != 0x04:
        raise ValueError("SGX public key must be 65 bytes: 0x04 || X_le || Y_le")
    return b"\x04" + public_key_sgx_le[1:33][::-1] + public_key_sgx_le[33:65][::-1]


def encrypt_key_ciphertext_v1(public_key_sgx_le: bytes, plaintext: bytes) -> bytes:
    """Encrypt DecKey input as EphemeralPK(65) || iv12 || tag16 || ct.

    The worker enclave consumes this in DecKey(). KMS prints public keys with
    little-endian SGX coordinates, while OpenSSL/Python expects X9.62 big-endian
    coordinates.
    """

    if len(plaintext) not in (16, 32):
        raise ValueError("KeyCiphertextV1 plaintext must be 16 or 32 bytes")

    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        sgx_le_public_key_to_x962_be(public_key_sgx_le),
    )
    ephemeral_sk = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_secret = ephemeral_sk.exchange(ec.ECDH(), public_key)[::-1]
    key = hashlib.sha256(shared_secret + b"ECC-IBE-ENC").digest()[:16]

    iv = os.urandom(12)
    ct_and_tag = AESGCM(key).encrypt(iv, plaintext, None)
    tag = ct_and_tag[-16:]
    ct = ct_and_tag[:-16]
    ephemeral_pk = ephemeral_sk.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return ephemeral_pk + iv + tag + ct


def build_artifact_plan(
    *,
    fid: str,
    wasm_bytes: bytes,
    input_bytes: bytes,
    k_func: bytes,
    k_req: bytes,
    pkU: bytes,
    nonce: bytes,
) -> ArtifactPlan:
    if len(k_func) != 16:
        raise ValueError("k_func must be 16 bytes")
    if len(k_req) != 16:
        raise ValueError("k_req must be 16 bytes")
    if len(pkU) != 65 or pkU[0] != 0x04:
        raise ValueError("pkU must be 65-byte uncompressed P-256 point")

    aead = AESGCMImpl()
    aad_pkg = build_aad_pkg(fid)
    c_func = aead.encrypt(k_func, wasm_bytes, aad_pkg)
    label = hashlib.sha256(c_func).hexdigest()
    aad_req = build_aad_req(fid, nonce, pkU)
    c_req = aead.encrypt(k_req, input_bytes, aad_req)
    rid = compute_rid(fid, c_req)
    return ArtifactPlan(
        fid=fid,
        label=label,
        rid=rid,
        aad_pkg=aad_pkg,
        aad_req=aad_req,
        c_func=c_func,
        c_req=c_req,
    )


def run_kms_print_pubkey(kms_dir: Path, identity: str) -> bytes:
    kms_dir = kms_dir.resolve()
    out_path = kms_dir / f".tmp-pubkey-{os.getpid()}-{hashlib.sha256(identity.encode()).hexdigest()[:12]}.bin"
    try:
        subprocess.run(
            ["./sgx_kms", "--print-pubkey", "--id", identity, "--out", str(out_path)],
            cwd=str(kms_dir),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        data = out_path.read_bytes()
    finally:
        try:
            out_path.unlink()
        except FileNotFoundError:
            pass
    if len(data) != 65 or data[0] != 0x04:
        raise ValueError(f"KMS public key for {identity} has invalid size/format")
    return data


def run_kms_bfibe_public_params(kms_dir: Path) -> bytes:
    kms_dir = kms_dir.resolve()
    out_path = kms_dir / f".tmp-bfibe-mpk-{os.getpid()}.bin"
    try:
        subprocess.run(
            ["./sgx_kms", "--bfibe-public-params", "--out", str(out_path)],
            cwd=str(kms_dir),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        data = out_path.read_bytes()
    finally:
        try:
            out_path.unlink()
        except FileNotFoundError:
            pass
    if len(data) == 0 or all(byte == 0 for byte in data):
        raise ValueError("KMS BF-IBE public params are empty or all-zero")
    return data


def build_bfibe_mcl_client_tool() -> Path:
    out = ACSC_ROOT / "_tmp" / "bfibe-mcl-client-tool" / "bfibe_mcl_client_tool"
    subprocess.run(
        [str(ACSC_ROOT / "scripts" / "build_bfibe_mcl_client_tool.sh"), "--out", str(out)],
        cwd=str(ACSC_ROOT),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return out


def run_bfibe_mcl_client_tool(
    *,
    tool_path: Path,
    mpk: bytes,
    purpose: str,
    identity: str,
    aad_context: bytes,
    plaintext: bytes,
    out_path: Path,
) -> bytes:
    if len(plaintext) not in (16, 32):
        raise ValueError("BF-IBE key plaintext must be 16 or 32 bytes")

    tmp_mpk = out_path.with_suffix(out_path.suffix + ".mpk")
    tmp_mpk.write_bytes(mpk)
    try:
        subprocess.run(
            [
                str(tool_path),
                "--mpk",
                str(tmp_mpk),
                "--purpose",
                purpose,
                "--identity",
                identity,
                "--aad-context-hex",
                aad_context.hex(),
                "--key-hex",
                plaintext.hex(),
                "--out",
                str(out_path),
            ],
            cwd=str(ACSC_ROOT),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    finally:
        try:
            tmp_mpk.unlink()
        except FileNotFoundError:
            pass
    return out_path.read_bytes()


def build_worker_smoke_artifacts(
    *,
    fid: str,
    wasm_path: Path,
    input_bytes: bytes,
    kms_dir: Path,
    out_dir: Path,
    k_func: Optional[bytes] = None,
    k_req: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
    crypto_profile: str = "eccibe",
) -> WorkerSmokeArtifacts:
    out_dir.mkdir(parents=True, exist_ok=True)
    profile = get_crypto_profile(crypto_profile)
    k_func = k_func or os.urandom(16)
    k_req = k_req or os.urandom(16)
    nonce = nonce or os.urandom(16)
    pkU, skU = P256HKDFKEM().keygen()

    plan = build_artifact_plan(
        fid=fid,
        wasm_bytes=wasm_path.read_bytes(),
        input_bytes=input_bytes,
        k_func=k_func,
        k_req=k_req,
        pkU=pkU,
        nonce=nonce,
    )

    paths = {
        "c_func": out_dir / "c_func.enc",
        "c_req": out_dir / "c_req.enc",
        "c_k_func": out_dir / "c_k_func.enc",
        "c_key": out_dir / "c_key.enc",
        "pkU": out_dir / "pkU.bin",
        "skU": out_dir / "skU.bin",
        "nonce": out_dir / "nonce.bin",
        "metadata": out_dir / "metadata.json",
    }
    paths["c_func"].write_bytes(plan.c_func)
    paths["c_req"].write_bytes(plan.c_req)

    if profile.profile_id == "eccibe":
        fid_pub = run_kms_print_pubkey(kms_dir, fid)
        label_pub = run_kms_print_pubkey(kms_dir, plan.label)
        paths["c_k_func"].write_bytes(encrypt_key_ciphertext_v1(label_pub, k_func))
        paths["c_key"].write_bytes(encrypt_key_ciphertext_v1(fid_pub, k_req))
    elif profile.profile_id == "bfibe-mcl-bls12381":
        mpk = run_kms_bfibe_public_params(kms_dir)
        tool_path = build_bfibe_mcl_client_tool()
        run_bfibe_mcl_client_tool(
            tool_path=tool_path,
            mpk=mpk,
            purpose="function-key",
            identity=f"label:{plan.label}",
            aad_context=plan.aad_pkg,
            plaintext=k_func,
            out_path=paths["c_k_func"],
        )
        run_bfibe_mcl_client_tool(
            tool_path=tool_path,
            mpk=mpk,
            purpose="request-key",
            identity=f"fid:{fid}",
            aad_context=plan.aad_req,
            plaintext=k_req,
            out_path=paths["c_key"],
        )
    else:
        raise ValueError(f"Unsupported worker smoke crypto profile: {profile.profile_id}")

    paths["pkU"].write_bytes(pkU)
    paths["skU"].write_bytes(skU)
    paths["nonce"].write_bytes(nonce)

    metadata = {
        "fid": fid,
        "label": plan.label,
        "rid": plan.rid,
        "files": {key: str(value) for key, value in paths.items() if key != "metadata"},
        "crypto_profile": profile.profile_id,
        "key_ciphertext_format": profile.key_ciphertext_format,
        "c_func_sha256": hashlib.sha256(plan.c_func).hexdigest(),
        "c_req_sha256": hashlib.sha256(plan.c_req).hexdigest(),
        "pkU_b64": base64.b64encode(pkU).decode("ascii"),
    }
    paths["metadata"].write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return WorkerSmokeArtifacts(
        fid=fid,
        label=plan.label,
        rid=plan.rid,
        c_func_path=paths["c_func"],
        c_req_path=paths["c_req"],
        c_k_func_path=paths["c_k_func"],
        c_key_path=paths["c_key"],
        pku_path=paths["pkU"],
        sku_path=paths["skU"],
        nonce_path=paths["nonce"],
        metadata_path=paths["metadata"],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fid", required=True)
    parser.add_argument("--wasm", required=True, type=Path)
    parser.add_argument("--input", default="", help="UTF-8 input payload")
    parser.add_argument("--kms-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--crypto-profile", default="eccibe")
    args = parser.parse_args()

    artifacts = build_worker_smoke_artifacts(
        fid=args.fid,
        wasm_path=args.wasm,
        input_bytes=args.input.encode("utf-8"),
        kms_dir=args.kms_dir,
        out_dir=args.out_dir,
        crypto_profile=args.crypto_profile,
    )
    print(artifacts.metadata_path.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
