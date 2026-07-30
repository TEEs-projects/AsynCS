import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
import zipfile
from io import BytesIO
from pathlib import Path

from flask import Flask, request, jsonify

ACSC_ROOT = Path(__file__).resolve().parents[1]
if str(ACSC_ROOT) not in sys.path:
    sys.path.append(str(ACSC_ROOT))

from crypto_lib.profiles import get_crypto_profile


app = Flask(__name__)

APP_DIR = os.environ.get("ACSC_RUNTIME_APP_DIR", "/app")
WORKER_PATH = os.environ.get("ACSC_RUNTIME_WORKER_PATH", str(Path(APP_DIR) / "sgx_worker"))
WORKER_CWD = os.environ.get("ACSC_RUNTIME_WORKER_CWD", APP_DIR)
RUNTIME_LIBS_DIR = os.environ.get("ACSC_RUNTIME_LIBS_DIR", str(Path(APP_DIR) / "libs"))
RUNTIME_HOST = os.environ.get("ACSC_RUNTIME_HOST", "all-interfaces")
RUNTIME_PORT = int(os.environ.get("ACSC_RUNTIME_PORT", "8080"))
WASM_FILE = os.environ.get("ACSC_RUNTIME_WASM_FILE", str(Path(APP_DIR) / "action.wasm.enc"))
INPUT_FILE = os.environ.get("ACSC_RUNTIME_INPUT_FILE", str(Path(APP_DIR) / "input.enc"))
CKFUNC_FILE = os.environ.get("ACSC_RUNTIME_CKFUNC_FILE", str(Path(APP_DIR) / "c_k_func.enc"))
CKEY_FILE = os.environ.get("ACSC_RUNTIME_CKEY_FILE", str(Path(APP_DIR) / "c_key.enc"))
PKU_FILE = os.environ.get("ACSC_RUNTIME_PKU_FILE", str(Path(APP_DIR) / "pku.bin"))
NONCE_FILE = os.environ.get("ACSC_RUNTIME_NONCE_FILE", str(Path(APP_DIR) / "nonce.bin"))
MAX_WORKER_ERROR_CHARS = int(os.environ.get("ACSC_RUNTIME_MAX_WORKER_ERROR_CHARS", "4000"))
PRESTART_WORKER = os.environ.get("ACSC_RUNTIME_PRESTART_WORKER", "0") == "1"
PRESTART_CRYPTO_PROFILE = os.environ.get("ACSC_RUNTIME_PRESTART_CRYPTO_PROFILE", "")
DEFAULT_OUTPUT_CAPACITY_BYTES = 4096
MAX_OUTPUT_CAPACITY_BYTES = 1024 * 1024
C5_MEASURED_RESULT_JSON_BYTES = 4096

# Ensure LD_LIBRARY_PATH includes the runtime libs directory for SGX/WAMR.
if RUNTIME_LIBS_DIR:
    os.environ["LD_LIBRARY_PATH"] = RUNTIME_LIBS_DIR + ":" + os.environ.get("LD_LIBRARY_PATH", "")

_SGX_WORKER_PROC = None
_SGX_WORKER_CRYPTO_PROFILE = None
_SGX_WORKER_LOCK = threading.Lock()
_LAST_WORKER_STARTED = False
_LAST_WORKER_STARTUP_MARKERS = {}

_TRACE_DURATION_MARKERS = {
    "ENCLAVE_CREATE_DUR_NS": "enclave_create_dur_ns",
    "ENCLAVE_INIT_DUR_NS": "enclave_init_dur_ns",
    "WORKER_KEYPATH_DUR_NS": "worker_keypath_dur_ns",
    "WORKER_WAIT_KMS_DUR_NS": "worker_wait_kms_dur_ns",
    "KMS_VERIFY_DUR_NS": "kms_verify_dur_ns",
    "KMS_KEY_RELEASE_DUR_NS": "kms_key_release_dur_ns",
    "KMS_TOTAL_DUR_NS": "kms_total_dur_ns",
    "QUOTE_GEN_DUR_NS": "quote_gen_dur_ns",
    "WORKER_EXEC_DUR_NS": "worker_exec_dur_ns",
    "WORKER_INVOKE_DUR_NS": "worker_invoke_dur_ns",
}

_WORKER_INVOKE_BOOL_FIELDS = {"key_cache_hit", "kms_contacted"}
_FUNCTION_CACHE_BOOL_FIELDS = {"function_cache_hit", "cfunc_decrypt_executed"}


class WorkerProtocolError(RuntimeError):
    pass


def _worker_protocol_tail(lines, limit=20):
    if not lines:
        return ""
    return "\n".join(lines[-limit:])


class UnsupportedCryptoProfileError(RuntimeError):
    pass


def _trim_worker_error(text):
    if text is None:
        return ""
    if len(text) <= MAX_WORKER_ERROR_CHARS:
        return text
    return text[-MAX_WORKER_ERROR_CHARS:]


def _worker_failed_response(reason, detail, rc=None):
    summary = _trim_worker_error(str(detail))
    print(f"Worker failed ({reason}): {summary}", file=sys.stderr, flush=True)
    payload = {
        "error": "Worker failed",
        "reason": reason,
        "stderr": summary,
    }
    if rc is not None:
        payload["rc"] = rc
    return jsonify(payload), 500


def _nonnegative_int(value):
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if parsed < 0:
        return None
    return parsed


_C5_TRACE_FIELDS = (
    "container_hostname",
    "worker_started_this_invocation",
    "worker_restart_reason",
    "kms_contacted",
    "enclave_key_cache_hit",
    "function_cache_hit",
    "crypto_profile",
    "key_ciphertext_format",
    "output_capacity_bytes",
    "payload_bytes_consumed",
    "payload_sha256",
    "adapter_invoke_dur_ns",
    "worker_exec_dur_ns",
    "worker_invoke_dur_ns",
    "input_key_decap_begin_cycles",
    "input_key_decap_end_cycles",
    "input_aes_gcm_begin_cycles",
    "input_aes_gcm_end_cycles",
    "workload_begin_cycles",
    "workload_end_cycles",
    "output_kem_begin_cycles",
    "output_kem_end_cycles",
    "output_aes_gcm_begin_cycles",
    "output_aes_gcm_end_cycles",
    "input_key_decap_duration_ns",
    "input_aes_gcm_duration_ns",
    "workload_core_duration_ns",
    "output_kem_duration_ns",
    "output_aes_gcm_duration_ns",
    "tsc_hz",
    "tsc_frequency_method",
)


def _c5_compact_trace(trace):
    compact = {
        "schema_version": "c5-asyncs-compact-trace-v1",
    }
    for field in _C5_TRACE_FIELDS:
        if field in trace:
            compact[field] = trace[field]
    events = trace.get("producer_timing_events")
    if isinstance(events, list):
        compact["producer_timing_events"] = [
            event
            for event in events
            if isinstance(event, dict) and event.get("event_code") in {"A400", "A410"}
        ]
    return compact


def _json_bytes(value):
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


def _c5_fixed_measured_response(response, target_bytes=C5_MEASURED_RESULT_JSON_BYTES):
    if target_bytes != C5_MEASURED_RESULT_JSON_BYTES:
        raise ValueError("C5 measured result size must be 4096 bytes")
    compact = dict(response)
    compact["trace"] = _c5_compact_trace(response.get("trace", {}))
    compact["measured_result_json_bytes"] = target_bytes
    compact["response_padding"] = ""
    padding_bytes = target_bytes - _json_bytes(compact)
    if padding_bytes < 0:
        raise ValueError("C5 compact measured result exceeds 4096 bytes")
    compact["response_padding"] = "0" * padding_bytes
    if _json_bytes(compact) != target_bytes:
        raise ValueError("C5 measured result padding mismatch")
    return compact


def _worker_timing_trace(markers):
    trace = {}
    for marker, trace_key in _TRACE_DURATION_MARKERS.items():
        parsed = _nonnegative_int(markers.get(marker))
        if parsed is not None:
            trace[trace_key] = parsed
    return trace


def _parse_structured_trace_fields(value, bool_fields=None):
    parsed = {}
    bool_fields = bool_fields or set()
    if not value:
        return parsed
    for token in str(value).split():
        if "=" not in token:
            continue
        key, raw = token.split("=", 1)
        if not key:
            continue
        if key in bool_fields:
            parsed[key] = raw in {"1", "true", "True"}
            continue
        numeric = _nonnegative_int(raw)
        parsed[key] = numeric if numeric is not None else raw
    return parsed


def _worker_structured_trace(markers):
    summary = _parse_structured_trace_fields(
        markers.get("ACSC_TRACE_WORKER_INVOKE"),
        bool_fields=_WORKER_INVOKE_BOOL_FIELDS,
    )
    if not summary:
        return {}
    return {"worker_invoke_summary": summary}


def _worker_function_cache_trace(markers):
    summary = _parse_structured_trace_fields(
        markers.get("ACSC_TRACE_FUNCTION_CACHE"),
        bool_fields=_FUNCTION_CACHE_BOOL_FIELDS,
    )
    if not summary:
        return {}
    trace = {"function_cache_summary": summary}
    for key in ("function_cache_hit", "cfunc_decrypt_executed", "function_cache_bytes"):
        if key in summary:
            trace[key] = summary[key]
    return trace


def _worker_e3_payload_trace(markers):
    summary = _parse_structured_trace_fields(markers.get("ACSC_TRACE_E3_PAYLOAD"))
    if not summary:
        return {}
    trace = {"e3_payload_summary": summary}
    if "payload_bytes_consumed" in summary:
        trace["payload_bytes_consumed"] = summary["payload_bytes_consumed"]
    if "payload_sha256" in summary:
        trace["payload_sha256"] = summary["payload_sha256"]
    return trace


def _worker_internal_timing_trace(markers):
    summary = _parse_structured_trace_fields(markers.get("ACSC_TRACE_INTERNAL_TIMING"))
    if not summary:
        return {}
    trace = {"internal_timing_summary": summary}
    for key in (
        "workload_timing_schema",
        "input_key_decap_begin_cycles",
        "input_key_decap_end_cycles",
        "input_aes_gcm_begin_cycles",
        "input_aes_gcm_end_cycles",
        "workload_begin_cycles",
        "workload_end_cycles",
        "output_kem_begin_cycles",
        "output_kem_end_cycles",
        "output_aes_gcm_begin_cycles",
        "output_aes_gcm_end_cycles",
        "function_key_decap_begin_cycles",
        "function_key_decap_end_cycles",
        "cfunc_aes_gcm_begin_cycles",
        "cfunc_aes_gcm_end_cycles",
        "wasm_load_begin_cycles",
        "wasm_load_end_cycles",
        "wasm_instantiate_begin_cycles",
        "wasm_instantiate_end_cycles",
        "input_key_decap_cycles",
        "input_aes_gcm_cycles",
        "workload_core_cycles",
        "output_kem_cycles",
        "output_aes_gcm_cycles",
        "function_key_decap_cycles",
        "cfunc_aes_gcm_cycles",
        "wasm_load_cycles",
        "wasm_instantiate_cycles",
        "tsc_hz",
        "tsc_frequency_method",
        "input_key_decap_duration_ns",
        "input_aes_gcm_duration_ns",
        "workload_core_duration_ns",
        "output_kem_duration_ns",
        "output_aes_gcm_duration_ns",
        "function_key_decap_duration_ns",
        "cfunc_aes_gcm_duration_ns",
        "wasm_load_duration_ns",
        "wasm_instantiate_duration_ns",
    ):
        if key in summary:
            trace[key] = summary[key]
    return trace


def _marker_int(markers, key):
    return _nonnegative_int(markers.get(key))


def _parse_marker_line(text):
    if ":" not in text:
        return None
    key, value = text.split(":", 1)
    if not key:
        return None
    return key, value.strip()


def _consume_worker_startup_markers_for_invocation():
    global _LAST_WORKER_STARTED, _LAST_WORKER_STARTUP_MARKERS
    if not _LAST_WORKER_STARTED:
        return {}
    markers = dict(_LAST_WORKER_STARTUP_MARKERS)
    _LAST_WORKER_STARTED = False
    _LAST_WORKER_STARTUP_MARKERS = {}
    return markers


def _timing_event(
    event_code,
    event_seq,
    *,
    process,
    unix_ns=None,
    mono_ns=None,
    logical_request_id=None,
    attempt_id=None,
    attrs=None,
):
    event_attrs = dict(attrs or {})
    if logical_request_id not in (None, ""):
        event_attrs["logical_request_id"] = str(logical_request_id)
    if attempt_id not in (None, ""):
        event_attrs["attempt_id"] = str(attempt_id)
    event = {
        "event_code": event_code,
        "event_seq": event_seq,
        "logical_request_id": str(logical_request_id) if logical_request_id not in (None, "") else "",
        "attempt_id": str(attempt_id) if attempt_id not in (None, "") else "",
        "process": process,
        "pid": os.getpid() if process == "asyncs_adapter" else "",
        "tid": "",
        "unix_ns": unix_ns if unix_ns is not None else "",
        "mono_ns": mono_ns if mono_ns is not None else "",
        "clock_domain": f"{process}_wall" if unix_ns is not None else f"{process}_mono",
        "status": "observed",
        "attrs": event_attrs,
    }
    return event


def _producer_timing_events(
    markers,
    *,
    startup_markers=None,
    adapter_begin_unix_ns,
    adapter_begin_mono_ns,
    adapter_end_unix_ns,
    adapter_end_mono_ns,
    logical_request_id=None,
    attempt_id=None,
):
    events = [
        _timing_event(
            "A200",
            200,
            process="asyncs_adapter",
            unix_ns=adapter_begin_unix_ns,
            mono_ns=adapter_begin_mono_ns,
            logical_request_id=logical_request_id,
            attempt_id=attempt_id,
            attrs={"boundary": "adapter_worker_invoke_enter"},
        ),
        _timing_event(
            "A210",
            210,
            process="asyncs_adapter",
            unix_ns=adapter_end_unix_ns,
            mono_ns=adapter_end_mono_ns,
            logical_request_id=logical_request_id,
            attempt_id=attempt_id,
            attrs={"boundary": "adapter_worker_invoke_exit"},
        ),
    ]
    startup_markers = startup_markers or {}
    startup_boundaries = [
        (
            "A320",
            320,
            "T_ENCLAVE_CREATE_BEGIN_MONO_NS",
            "enclave_create_enter",
        ),
        (
            "A330",
            330,
            "T_ENCLAVE_CREATE_END_MONO_NS",
            "enclave_create_exit",
        ),
        (
            "A340",
            340,
            "T_ENCLAVE_INIT_BEGIN_MONO_NS",
            "enclave_init_enter",
        ),
        (
            "A350",
            350,
            "T_ENCLAVE_INIT_END_MONO_NS",
            "enclave_init_exit",
        ),
    ]
    startup_values = [
        _marker_int(startup_markers, marker)
        for _, _, marker, _ in startup_boundaries
    ]
    if all(value is not None and value > 0 for value in startup_values):
        create_begin, create_end, init_begin, init_end = startup_values
        if create_begin <= create_end <= init_begin <= init_end:
            for event_code, event_seq, marker, boundary in startup_boundaries:
                events.append(
                    _timing_event(
                        event_code,
                        event_seq,
                        process="asyncs_worker",
                        mono_ns=_marker_int(startup_markers, marker),
                        logical_request_id=logical_request_id,
                        attempt_id=attempt_id,
                        attrs={
                            "boundary": boundary,
                            "source": "worker_startup_readiness",
                        },
                    )
                )
    kms_send = _marker_int(markers, "T_KMS_SEND_MONO_NS")
    kms_recv = _marker_int(markers, "T_KMS_RECV_MONO_NS")
    if kms_send is not None and kms_recv is not None and kms_recv >= kms_send and kms_send > 0:
        events.append(
            _timing_event(
                "A300",
                300,
                process="asyncs_worker",
                mono_ns=kms_send,
                logical_request_id=logical_request_id,
                attempt_id=attempt_id,
                attrs={"boundary": "kms_request_enter"},
            )
        )
        events.append(
            _timing_event(
                "A310",
                310,
                process="asyncs_worker",
                mono_ns=kms_recv,
                logical_request_id=logical_request_id,
                attempt_id=attempt_id,
                attrs={"boundary": "kms_response_exit"},
            )
        )
    exec_begin_unix = _marker_int(markers, "T_EXEC_BEGIN_NS")
    exec_end_unix = _marker_int(markers, "T_EXEC_END_NS")
    exec_begin_mono = _marker_int(markers, "T_EXEC_BEGIN_MONO_NS")
    exec_end_mono = _marker_int(markers, "T_EXEC_END_MONO_NS")
    if exec_begin_unix is not None and exec_end_unix is not None and exec_end_unix >= exec_begin_unix:
        events.append(
            _timing_event(
                "A400",
                400,
                process="asyncs_worker",
                unix_ns=exec_begin_unix,
                mono_ns=exec_begin_mono,
                logical_request_id=logical_request_id,
                attempt_id=attempt_id,
                attrs={"boundary": "function_execute_enter"},
            )
        )
        events.append(
            _timing_event(
                "A410",
                410,
                process="asyncs_worker",
                unix_ns=exec_end_unix,
                mono_ns=exec_end_mono,
                logical_request_id=logical_request_id,
                attempt_id=attempt_id,
                attrs={"boundary": "function_execute_exit"},
            )
        )
    return events


def _parse_worker_response(lines):
    rc = None
    in_response = False
    saw_end = False
    payload_lines = []
    markers = {}

    for text in lines:
        if text == "BEGIN_RESPONSE":
            in_response = True
            continue
        if text == "END_RESPONSE":
            saw_end = True
            break
        if not in_response:
            continue
        if text.startswith("RC:"):
            rc = int(text.split(":", 1)[1].strip() or "0")
            continue
        payload_lines.append(text)
        if ":" in text:
            key, value = text.split(":", 1)
            markers[key] = value.strip()

    if not saw_end:
        raise WorkerProtocolError("missing END_RESPONSE")
    if rc is None:
        raise WorkerProtocolError("missing RC")
    return rc, "\n".join(payload_lines), markers


def _start_sgx_worker(crypto_profile_id="eccibe"):
    global _SGX_WORKER_PROC, _SGX_WORKER_CRYPTO_PROFILE, _LAST_WORKER_STARTED, _LAST_WORKER_STARTUP_MARKERS
    requested_profile = crypto_profile_id or "eccibe"
    if (
        _SGX_WORKER_PROC is not None
        and _SGX_WORKER_PROC.poll() is None
        and _SGX_WORKER_CRYPTO_PROFILE == requested_profile
    ):
        _LAST_WORKER_STARTED = False
        _LAST_WORKER_STARTUP_MARKERS = {}
        return
    if _SGX_WORKER_PROC is not None:
        _stop_sgx_worker()

    worker_env = os.environ.copy()
    worker_env["ASYNCS_CRYPTO_PROFILE"] = requested_profile

    _SGX_WORKER_PROC = subprocess.Popen(
        [WORKER_PATH, "--server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=WORKER_CWD,
        env=worker_env,
    )
    _SGX_WORKER_CRYPTO_PROFILE = requested_profile
    _LAST_WORKER_STARTED = True
    _LAST_WORKER_STARTUP_MARKERS = {}
    if _SGX_WORKER_PROC.stdout is None:
        raise WorkerProtocolError("worker started without stdout")

    readiness_lines = []
    startup_markers = {}
    for _ in range(200):
        line = _SGX_WORKER_PROC.stdout.readline()
        if not line:
            break
        text = line.rstrip("\n")
        readiness_lines.append(text)
        marker = _parse_marker_line(text)
        if marker is not None:
            key, value = marker
            startup_markers[key] = value
        if text == "SERVER_READY":
            _LAST_WORKER_STARTUP_MARKERS = startup_markers
            return
    tail = "\n".join(readiness_lines[-5:])
    _LAST_WORKER_STARTUP_MARKERS = {}
    raise WorkerProtocolError(f"worker did not emit SERVER_READY: {tail}")


def _stop_sgx_worker():
    global _SGX_WORKER_PROC, _SGX_WORKER_CRYPTO_PROFILE
    proc = _SGX_WORKER_PROC
    _SGX_WORKER_PROC = None
    _SGX_WORKER_CRYPTO_PROFILE = None
    if proc is None:
        return
    try:
        if proc.stdin:
            proc.stdin.write("exit\n")
            proc.stdin.flush()
    except Exception:
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.terminate()


def _prestart_sgx_worker_if_enabled():
    if not PRESTART_WORKER:
        return
    if PRESTART_CRYPTO_PROFILE != "bfibe-mcl-bls12381":
        raise WorkerProtocolError(
            "enclave-ready prewarm requires bfibe-mcl-bls12381"
        )

    _start_sgx_worker(PRESTART_CRYPTO_PROFILE)
    required_markers = (
        "T_ENCLAVE_CREATE_BEGIN_MONO_NS",
        "T_ENCLAVE_CREATE_END_MONO_NS",
        "T_ENCLAVE_INIT_BEGIN_MONO_NS",
        "T_ENCLAVE_INIT_END_MONO_NS",
    )
    missing = [key for key in required_markers if key not in _LAST_WORKER_STARTUP_MARKERS]
    if missing:
        _stop_sgx_worker()
        raise WorkerProtocolError(
            "prestarted worker reached SERVER_READY without enclave lifecycle markers: "
            + ",".join(missing)
        )
    if _LAST_WORKER_STARTUP_MARKERS.get("KMS_CONTACTED") == "1":
        _stop_sgx_worker()
        raise WorkerProtocolError("prestarted worker contacted KMS before an invocation")

    print(
        "ACSC_RUNTIME_PREWARM_READY:"
        f"crypto_profile={PRESTART_CRYPTO_PROFILE} "
        "worker=running enclave=ready kms_contacted=0 workload_loaded=0",
        flush=True,
    )


def _invoke_sgx_worker(tokens, crypto_profile_id="eccibe"):
    with _SGX_WORKER_LOCK:
        _start_sgx_worker(crypto_profile_id)
        worker_started_this_invocation = bool(_LAST_WORKER_STARTED)
        startup_markers = _consume_worker_startup_markers_for_invocation()
        proc = _SGX_WORKER_PROC
        if proc is None or proc.stdin is None or proc.stdout is None:
            raise WorkerProtocolError("worker_not_running")
        proc.stdin.write(" ".join(tokens) + "\n")
        proc.stdin.flush()
        lines = []
        while True:
            line = proc.stdout.readline()
            if not line:
                rc = proc.poll()
                tail = _worker_protocol_tail(lines)
                detail = f"worker exited before END_RESPONSE rc={rc}"
                if tail:
                    detail = f"{detail}\nworker_output_tail:\n{tail}"
                raise WorkerProtocolError(detail)
            text = line.rstrip("\n")
            lines.append(text)
            if text == "END_RESPONSE":
                break
        rc, combined, markers = _parse_worker_response(lines)
        return rc, combined, markers, worker_started_this_invocation, startup_markers


def _require_field(value: dict, key: str) -> str:
    v = value.get(key)
    if v is None or v == "":
        raise ValueError(f"Missing required field: {key}")
    if not isinstance(v, str):
        raise ValueError(f"Invalid type for field {key}: expected string")
    return v


def _optional_string_field(value: dict, key: str):
    v = value.get(key)
    if v is None or v == "":
        return None
    if not isinstance(v, str):
        raise ValueError(f"Invalid type for field {key}: expected string")
    return v


def _resolve_crypto_metadata(value: dict):
    profile_name = _optional_string_field(value, "crypto_profile")
    requested_format = _optional_string_field(value, "key_ciphertext_format")
    profile = get_crypto_profile(profile_name)
    key_ciphertext_format = requested_format or profile.key_ciphertext_format

    if key_ciphertext_format != profile.key_ciphertext_format:
        raise ValueError(
            "Invalid key_ciphertext_format for crypto_profile "
            f"{profile.profile_id}: expected {profile.key_ciphertext_format}, "
            f"got {key_ciphertext_format}"
        )

    return profile


def _write_b64_file(path: str, b64_value: str) -> bytes:
    raw = base64.b64decode(b64_value)
    with open(path, "wb") as f:
        f.write(raw)
    return raw


def _remove_file(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


@app.route('/init', methods=['POST'])
def init():
    data = request.get_json(force=True) or {}
    code = data.get('value', {}).get('code')
    if not code:
        return jsonify({"error": "No code provided"}), 400

    try:
        if isinstance(code, dict) and isinstance(code.get("data"), list):
            wasm_bytes = bytes(code["data"])
        elif isinstance(code, str):
            wasm_bytes = base64.b64decode(code)
        else:
            return jsonify({"error": "bad code type"}), 400

        if wasm_bytes.startswith(b"PK\x03\x04"):
            zf = zipfile.ZipFile(BytesIO(wasm_bytes))
            wasm_bytes = zf.read("action.wasm.enc")

        with open(WASM_FILE, 'wb') as f:
            f.write(wasm_bytes)

        module_sha256 = hashlib.sha256(wasm_bytes).hexdigest()
        return jsonify({
            "ok": True,
            "module_sha256": module_sha256,
            "module_size": len(wasm_bytes),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/reset', methods=['POST'])
def reset():
    with _SGX_WORKER_LOCK:
        _stop_sgx_worker()
    return jsonify({"ok": True, "explicit_reset": True})


@app.route('/run', methods=['POST'])
def run():
    data = request.get_json(force=True) or {}
    value = data.get('value', {})

    try:
        fid = _require_field(value, "FID")
        encrypted_input_b64 = _require_field(value, "encrypted_input")
        c_k_func_b64 = _require_field(value, "C_k_func")
        c_key_b64 = _require_field(value, "C_key")
        pku_b64 = _require_field(value, "pkU")
        nonce_b64 = _require_field(value, "nonce")
        crypto_profile = _resolve_crypto_metadata(value)
        label = value.get("label", "default_label")
        if not isinstance(label, str) or not label:
            raise ValueError("Invalid type for field label: expected non-empty string")
        output_capacity_bytes = value.get(
            "output_capacity_bytes", DEFAULT_OUTPUT_CAPACITY_BYTES
        )
        if (
            type(output_capacity_bytes) is not int
            or output_capacity_bytes <= 0
            or output_capacity_bytes > MAX_OUTPUT_CAPACITY_BYTES
        ):
            raise ValueError(
                "Invalid output_capacity_bytes: expected integer in [1, 1048576]"
            )
        c5_result_json_bytes = value.get("c5_result_json_bytes")
        if c5_result_json_bytes is not None:
            if value.get("c5_schema_version") != "c5-asyncs-request-v1":
                raise ValueError("C5 measured result requires c5-asyncs-request-v1")
            if c5_result_json_bytes != C5_MEASURED_RESULT_JSON_BYTES:
                raise ValueError("C5 measured result size must be 4096 bytes")
    except UnsupportedCryptoProfileError as e:
        return jsonify({"error": str(e)}), 501
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    per_request_files = [INPUT_FILE, CKEY_FILE, PKU_FILE, NONCE_FILE]

    try:
        _write_b64_file(INPUT_FILE, encrypted_input_b64)
        _write_b64_file(CKFUNC_FILE, c_k_func_b64)
        _write_b64_file(CKEY_FILE, c_key_b64)
        _write_b64_file(PKU_FILE, pku_b64)
        _write_b64_file(NONCE_FILE, nonce_b64)

        tokens = [
            "invoke",
            fid,
            WASM_FILE,
            INPUT_FILE,
            "--label",
            label,
            "--keys",
            CKFUNC_FILE,
            CKEY_FILE,
            "--max-output-bytes",
            str(output_capacity_bytes),
            PKU_FILE,
            NONCE_FILE,
        ]

        try:
            adapter_invoke_begin_unix_ns = time.time_ns()
            adapter_invoke_begin_ns = time.perf_counter_ns()
            rc, combined, markers, worker_started_this_invocation, startup_markers = _invoke_sgx_worker(
                tokens,
                crypto_profile.profile_id,
            )
            adapter_invoke_end_unix_ns = time.time_ns()
            adapter_invoke_end_ns = time.perf_counter_ns()
            adapter_invoke_dur_ns = max(0, adapter_invoke_end_ns - adapter_invoke_begin_ns)
        except Exception as e:
            return _worker_failed_response("protocol", e)

        if rc != 0:
            return _worker_failed_response("nonzero_rc", combined, rc=rc)

        res_hex = markers.get("RESULT_HEX")
        ct_hex = markers.get("CT_HEX")
        rid_hex = markers.get("RID_HEX")

        if res_hex is None:
            return jsonify({"error": "No result found in worker output", "stdout": combined}), 500

        trace_markers = {**startup_markers, **markers}
        trace = {
            "worker_started_this_invocation": worker_started_this_invocation,
            "worker_restart_reason": "none",
            "kms_contacted": trace_markers.get("KMS_CONTACTED") == "1",
            "enclave_key_cache_hit": trace_markers.get("ENCLAVE_KEY_CACHE_HIT") == "1",
            "worker_invoke_rc": rc,
            "container_hostname": socket.gethostname(),
            "adapter_invoke_dur_ns": adapter_invoke_dur_ns,
            "crypto_profile": crypto_profile.profile_id,
            "key_ciphertext_format": crypto_profile.key_ciphertext_format,
            "output_capacity_bytes": output_capacity_bytes,
        }
        trace.update(_worker_timing_trace(trace_markers))
        trace.update(_worker_structured_trace(trace_markers))
        trace.update(_worker_function_cache_trace(trace_markers))
        trace.update(_worker_e3_payload_trace(trace_markers))
        trace.update(_worker_internal_timing_trace(trace_markers))
        trace["producer_timing_events"] = _producer_timing_events(
            trace_markers,
            startup_markers=startup_markers,
            adapter_begin_unix_ns=adapter_invoke_begin_unix_ns,
            adapter_begin_mono_ns=adapter_invoke_begin_ns,
            adapter_end_unix_ns=adapter_invoke_end_unix_ns,
            adapter_end_mono_ns=adapter_invoke_end_ns,
            logical_request_id=value.get("logical_request_id"),
            attempt_id=value.get("attempt_id"),
        )

        resp = {
            "C_out": base64.b64encode(bytes.fromhex(res_hex)).decode("utf-8"),
            "trace": trace,
        }
        if ct_hex is not None:
            resp["ct"] = base64.b64encode(bytes.fromhex(ct_hex)).decode("utf-8")
        if rid_hex is not None:
            resp["rid"] = rid_hex

        if value.get("force_action_failure"):
            trace["harness_action_failure"] = True
            resp["error"] = {
                "message": value.get("failure_reason") or "harness action-level failure",
                "harness_action_failure": True,
                "trace": trace,
            }
            if rid_hex is not None:
                resp["error"]["rid"] = rid_hex

        if c5_result_json_bytes is not None:
            resp = _c5_fixed_measured_response(resp, c5_result_json_bytes)

        return jsonify(resp)
    except Exception as e:
        print(f"Runtime adapter failed: {e}", file=sys.stderr)
        return jsonify({"error": str(e)}), 500
    finally:
        for path in per_request_files:
            _remove_file(path)


def main():
    _prestart_sgx_worker_if_enabled()
    app.run(host=RUNTIME_HOST, port=RUNTIME_PORT)


if __name__ == '__main__':
    main()
