#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKER_APP = ROOT / "sgx_worker" / "App" / "App.cpp"


def test_sim_quote_embeds_enclave_report_body_for_kms_report_data_binding() -> None:
    source = WORKER_APP.read_text(encoding="utf-8")

    assert "WORKER_QUOTE3_REPORT_BODY_OFFSET" in source
    assert "WORKER_REPORT_BODY_SIZE" in source
    assert "embed_report_in_sim_quote" in source
    assert "report->body.report_data.d" in source
    assert "WORKER_REPORT_DATA_OFFSET_IN_BODY" in source
    assert "memcpy(quote + WORKER_QUOTE3_REPORT_BODY_OFFSET" in source
    assert "embed_report_in_sim_quote(quote.data(), (uint32_t)quote.size(), report)" in source


def test_sim_quote_generation_uses_enclave_report_not_plain_fill_bytes() -> None:
    source = WORKER_APP.read_text(encoding="utf-8")

    assert "ecall_create_report(global_eid, &dummy_target_info, &dummy_report, public_key);" in source
    assert "embed_report_in_sim_quote(quote_out, &dummy_report)" in source
    assert "embed_report_in_sim_quote(p_quote_buffer, quote_size, &dummy_report)" in source
