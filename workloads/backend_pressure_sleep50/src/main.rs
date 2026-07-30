use std::thread;
use std::time::Duration;

#[link(wasm_import_module = "env")]
extern "C" {
    fn c1_workload_tsc_begin() -> u64;
    fn c1_workload_tsc_end() -> u64;
    fn c1_workload_set_output(data: *const u8, len: usize) -> i32;
}

const SLEEP_MS: u64 = 50;

fn main() {
    let workload_started = unsafe { c1_workload_tsc_begin() };
    thread::sleep(Duration::from_millis(SLEEP_MS));
    let workload_finished = unsafe { c1_workload_tsc_end() };
    let workload_core_cycles = workload_finished.saturating_sub(workload_started);

    let output = format!(
        "{{\"workload_id\":\"asyncs-wasm-sleep-50ms\",\"workload_logic_hash\":\"rust-std-thread-sleep-50ms-v1\",\"workload_kind\":\"wasm_sleep\",\"workload_input_bytes\":0,\"workload_input_mode\":\"none\",\"workload_compress_level\":0,\"workload_timing_schema\":\"enclave-rdtsc-v1\",\"workload_core_cycles\":{},\"workload_input_sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"workload_output_bytes\":0,\"workload_output_sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"workload_input_consumed\":true,\"workload_sleep_ms\":{}}}",
        workload_core_cycles,
        SLEEP_MS,
    );
    let status = unsafe { c1_workload_set_output(output.as_ptr(), output.len()) };
    assert_eq!(status, 0, "publish workload output");
}
