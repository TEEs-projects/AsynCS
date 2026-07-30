#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KMS_APP_CPP = ROOT / "sgx_kms" / "App" / "App.cpp"
WORKER_APP_CPP = ROOT / "sgx_worker" / "App" / "App.cpp"


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_kms_success_response_appends_breakdown_timing_trailer() -> None:
    source = _source(KMS_APP_CPP)

    assert "struct KmsTimingTrailer" in source
    assert "static_assert(sizeof(KmsTimingTrailer) == sizeof(uint64_t) * 3" in source
    assert "kms_verify_dur_ns" in source
    assert "kms_key_release_dur_ns" in source
    assert "kms_total_dur_ns" in source
    assert source.count("send_keys_with_timing(client_socket, combined_keys") >= 2


def test_worker_reads_full_kms_response_before_parsing_timing_trailer() -> None:
    source = _source(WORKER_APP_CPP)

    assert "read_kms_response(sock, buffer, sizeof(buffer))" in source
    assert "int valread = read(sock, buffer, 1024);" not in source


def test_worker_parses_kms_timing_trailer_after_key_bytes() -> None:
    source = _source(WORKER_APP_CPP)

    assert "struct KmsTimingTrailer" in source
    assert "static const int KMS_KEYS_LEN = 248" in source
    assert "static const int KMS_TIMING_TRAILER_LEN" in source
    assert "memcpy(&timing, buffer + KMS_KEYS_LEN, sizeof(timing))" in source
    assert "g_kms_verify_dur_ns = timing.verify_dur_ns" in source
    assert "g_kms_key_release_dur_ns = timing.key_release_dur_ns" in source
    assert "g_kms_total_dur_ns = timing.total_dur_ns" in source


def test_kms_bfibe_success_response_appends_breakdown_timing_trailer() -> None:
    source = _source(KMS_APP_CPP)

    assert "send_bfibe_release_with_timing" in source
    assert "memcpy(response + actual_release_size, &timing, sizeof(timing))" in source
    assert "kms_verify_dur_ns" in source
    assert "kms_key_release_dur_ns" in source
    assert "kms_total_begin_ns" in source


def test_worker_splits_bfibe_payload_before_timing_trailer() -> None:
    source = _source(WORKER_APP_CPP)

    assert "static int bfibe_key_release_payload_len" in source
    assert "int bfibe_release_len = bfibe_key_release_payload_len(buffer, valread)" in source
    assert "ecall_load_bfibe_key_release(" in source
    assert "(uint32_t)bfibe_release_len" in source
    assert "memcpy(&timing, buffer + bfibe_release_len, sizeof(timing))" in source
    assert "g_kms_verify_dur_ns = timing.verify_dur_ns" in source
    assert "g_kms_key_release_dur_ns = timing.key_release_dur_ns" in source
    assert "g_kms_total_dur_ns = timing.total_dur_ns" in source
