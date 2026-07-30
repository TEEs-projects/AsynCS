#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_worker_sends_crypto_profile_in_kms_request():
    app = (ROOT / "sgx_worker" / "App" / "App.cpp").read_text()

    assert "kms_crypto_profile()" in app
    assert 'getenv("ASYNCS_CRYPTO_PROFILE")' in app
    assert "crypto_profile_len" in app
    assert "write_u32(sock, crypto_profile_len)" in app
    assert "write_exact(sock, crypto_profile, crypto_profile_len)" in app


def test_worker_kms_request_uses_exact_writes_for_all_fields():
    app = (ROOT / "sgx_worker" / "App" / "App.cpp").read_text()

    assert "write_u32(sock, quote_size)" in app
    assert "write_exact(sock, quote, quote_size)" in app
    assert "write_u32(sock, fid_len)" in app
    assert "write_exact(sock, fid, fid_len)" in app
    assert "write_u32(sock, label_len)" in app
    assert "write_exact(sock, label, label_len)" in app
    assert "write_exact(sock, public_key, 64)" in app
    assert "KMS request send failed" in app


def test_kms_socket_dispatches_bfibe_profile_to_variable_release_ecall():
    app = (ROOT / "sgx_kms" / "App" / "App.cpp").read_text()

    assert "crypto_profile_len" in app
    assert "crypto_profile" in app
    assert "read_exact(int fd, void* data, size_t len)" in app
    assert "read_u32(client_socket, &quote_size)" in app
    assert "read_exact(client_socket, quote, quote_size)" in app
    assert "read_exact(client_socket, public_key, 64)" in app
    assert "read_exact(client_socket, crypto_profile, crypto_profile_len)" in app
    assert 'strcmp(crypto_profile, "bfibe-mcl-bls12381") == 0' in app
    assert "ecall_get_bfibe_key_release" in app
    assert "send_bfibe_release_with_timing" in app
    assert "memcpy(response, bfibe_release, actual_release_size)" in app
    assert "memcpy(response + actual_release_size, &timing, sizeof(timing))" in app
    assert "send_all(client_socket, response, actual_release_size + sizeof(timing))" in app


def test_kms_socket_keeps_eccibe_on_legacy_batch_path():
    app = (ROOT / "sgx_kms" / "App" / "App.cpp").read_text()
    bf_idx = app.index('strcmp(crypto_profile, "bfibe-mcl-bls12381") == 0')
    legacy_idx = app.index("ecall_derive_keys_batch", bf_idx)

    assert bf_idx < legacy_idx
    assert 'strcmp(crypto_profile, "eccibe") != 0' in app


def test_kms_listener_backlog_is_configurable_for_cold_start_bursts():
    app = (ROOT / "sgx_kms" / "App" / "App.cpp").read_text()

    assert "kms_listen_backlog()" in app
    assert '"KMS_LISTEN_BACKLOG"' in app
    assert "listen(server_fd, backlog)" in app
    assert 'printf("\\nKMS Server listening on port %d backlog %d\\n", PORT, backlog)' in app


def test_worker_retries_kms_connect_with_jitter():
    app = (ROOT / "sgx_worker" / "App" / "App.cpp").read_text()

    assert "kms_connect_attempts()" in app
    assert '"KMS_CONNECT_ATTEMPTS"' in app
    assert "kms_connect_retry_sleep_ms()" in app
    assert "KMS connect retry" in app
    assert "nanosleep(&sleep_time, NULL)" in app
