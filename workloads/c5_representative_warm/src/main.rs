use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::io::Write;
#[cfg(not(test))]
use std::{env, thread, time::Duration};

#[cfg(not(test))]
#[link(wasm_import_module = "env")]
extern "C" {
    fn c1_workload_tsc_begin() -> u64;
    fn c1_workload_tsc_end() -> u64;
    fn c1_workload_set_output(data: *const u8, len: usize) -> i32;
}

const SUITE_ID: &str = "c5-representative-warm-v1";
const DYNAMIC_ID: &str = "dynamic-html-derived-v1";
const DYNAMIC_LOGIC: &str = "c5-dynamic-html-portable-render-v1";
const COMPRESSION_ID: &str = "compression-derived-random256k-level6-v1";
const COMPRESSION_LOGIC: &str = "c5-gzip-level6-random256k-v1";
const SLEEP_ID: &str = "sleep50-path-control-v1";
const SLEEP_LOGIC: &str = "c5-async-sleep50-v1";
const DYNAMIC_TEMPLATE: &str = include_str!(env!("C5_DYNAMIC_TEMPLATE_PATH"));
const DYNAMIC_DATA: &str = include_str!(env!("C5_DYNAMIC_DATA_PATH"));
const DYNAMIC_EXPECTED: &[u8] = include_bytes!(env!("C5_DYNAMIC_EXPECTED_PATH"));
const COMPRESSION_INPUT: &[u8] = include_bytes!(env!("C5_COMPRESSION_INPUT_PATH"));
const SLEEP_INPUT: &[u8] = b"{\"sleep_ms\":50}";
const SLEEP_OUTPUT: &[u8] =
    b"{\"ok\":true,\"slept_ms\":50,\"workload_id\":\"sleep50-path-control-v1\"}";
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Debug, PartialEq)]
struct Command {
    logical_request_id: String,
    ordinal: u64,
    phase: &'static str,
    workload_code: char,
}

struct WorkloadResult {
    workload_id: &'static str,
    workload_logic_hash: &'static str,
    input: Vec<u8>,
    output: Vec<u8>,
}

fn decode_digit(value: u8) -> Result<u8, &'static str> {
    match value {
        b'A'..=b'Z' => Ok(value - b'A'),
        b'a'..=b'z' => Ok(value - b'a' + 26),
        b'0'..=b'9' => Ok(value - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("invalid base64 digit"),
    }
}

fn decode_base64(value: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = value.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err("base64 length is not a multiple of four");
    }
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let final_chunk = index + 1 == bytes.len() / 4;
        let pad = match (chunk[2], chunk[3]) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            (b'=', _) => return Err("invalid base64 padding"),
            _ => 0,
        };
        if pad > 0 && !final_chunk {
            return Err("base64 padding before final chunk");
        }
        let a = decode_digit(chunk[0])? as u32;
        let b = decode_digit(chunk[1])? as u32;
        let c = if pad == 2 {
            0
        } else {
            decode_digit(chunk[2])? as u32
        };
        let d = if pad > 0 {
            0
        } else {
            decode_digit(chunk[3])? as u32
        };
        let word = (a << 18) | (b << 12) | (c << 6) | d;
        output.push((word >> 16) as u8);
        if pad < 2 {
            output.push((word >> 8) as u8);
        }
        if pad == 0 {
            output.push(word as u8);
        }
    }
    Ok(output)
}

fn encode_base64(bytes: &[u8]) -> String {
    let mut output = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0] as u32;
        let b = chunk.get(1).copied().unwrap_or(0) as u32;
        let c = chunk.get(2).copied().unwrap_or(0) as u32;
        let word = (a << 16) | (b << 8) | c;
        output.push(BASE64[((word >> 18) & 0x3f) as usize] as char);
        output.push(BASE64[((word >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            BASE64[((word >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            BASE64[(word & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn field_value<'a>(input: &'a str, key: &str) -> Result<&'a str, &'static str> {
    let needle = format!("\"{}\"", key);
    let key_end = input.find(&needle).ok_or("missing field")? + needle.len();
    let remainder = input[key_end..].trim_start();
    let remainder = remainder
        .strip_prefix(':')
        .ok_or("missing field separator")?
        .trim_start();
    Ok(remainder)
}

fn string_field(input: &str, key: &str) -> Result<String, &'static str> {
    let remainder = field_value(input, key)?;
    let remainder = remainder.strip_prefix('"').ok_or("invalid string field")?;
    let end = remainder.find('"').ok_or("unterminated string field")?;
    let value = &remainder[..end];
    if value.contains('\\') {
        return Err("escaped command strings are not supported");
    }
    Ok(value.to_string())
}

fn u64_field(input: &str, key: &str) -> Result<u64, &'static str> {
    let digits: String = field_value(input, key)?
        .chars()
        .take_while(|value| value.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return Err("invalid integer field");
    }
    digits.parse().map_err(|_| "invalid integer field")
}

fn parse_command(input: &[u8]) -> Result<Command, &'static str> {
    let text = std::str::from_utf8(input).map_err(|_| "command is not utf8")?;
    if string_field(text, "s")? != "v1" {
        return Err("command schema mismatch");
    }
    let phase = match string_field(text, "p")?.as_str() {
        "p" => "correctness_probe",
        "m" => "measured",
        _ => return Err("command phase mismatch"),
    };
    let workload = string_field(text, "w")?;
    let workload_code = match workload.as_str() {
        "d" => 'd',
        "g" => 'g',
        "s" => 's',
        _ => return Err("command workload mismatch"),
    };
    Ok(Command {
        logical_request_id: string_field(text, "a")?,
        ordinal: u64_field(text, "o")?,
        phase,
        workload_code,
    })
}

fn dynamic_string(key: &str) -> String {
    string_field(DYNAMIC_DATA, key).expect("valid fixed dynamic-html data")
}

fn dynamic_u64(key: &str) -> u64 {
    u64_field(DYNAMIC_DATA, key).expect("valid fixed dynamic-html data")
}

fn canonical_dynamic_data() -> String {
    format!(
        "{{\"item_count\":{},\"item_value_modulus\":{},\"item_value_multiplier\":{},\"render_iterations\":{},\"title\":\"{}\",\"user_name\":\"{}\",\"user_role\":\"{}\"}}",
        dynamic_u64("item_count"),
        dynamic_u64("item_value_modulus"),
        dynamic_u64("item_value_multiplier"),
        dynamic_u64("render_iterations"),
        dynamic_string("title"),
        dynamic_string("user_name"),
        dynamic_string("user_role"),
    )
}

fn render_html() -> String {
    let item_count = dynamic_u64("item_count");
    let multiplier = dynamic_u64("item_value_multiplier");
    let modulus = dynamic_u64("item_value_modulus");
    let mut rows = String::new();
    for index in 0..item_count {
        let id = index + 1;
        let enabled = if index % 3 != 0 { "true" } else { "false" };
        rows.push_str(&format!(
            "<li data-id=\"{}\" data-enabled=\"{}\"><span>item-{:03}</span><strong>{}</strong></li>",
            id,
            enabled,
            id,
            (index * multiplier) % modulus,
        ));
    }
    DYNAMIC_TEMPLATE
        .replace("{{title}}", &dynamic_string("title"))
        .replacen("{{user_name}}", &dynamic_string("user_name"), 1)
        .replacen("{{user_role}}", &dynamic_string("user_role"), 1)
        .replacen("{{item_rows}}", &rows, 1)
        .replacen("{{item_count}}", &item_count.to_string(), 1)
}

fn dynamic_html() -> WorkloadResult {
    let canonical_data = canonical_dynamic_data();
    let mut input = Vec::with_capacity(DYNAMIC_TEMPLATE.len() + canonical_data.len());
    input.extend_from_slice(DYNAMIC_TEMPLATE.as_bytes());
    input.extend_from_slice(canonical_data.as_bytes());
    let mut output = String::new();
    for _ in 0..dynamic_u64("render_iterations") {
        output = render_html();
    }
    WorkloadResult {
        workload_id: DYNAMIC_ID,
        workload_logic_hash: DYNAMIC_LOGIC,
        input,
        output: output.into_bytes(),
    }
}

fn compression() -> WorkloadResult {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(COMPRESSION_INPUT).expect("gzip input");
    WorkloadResult {
        workload_id: COMPRESSION_ID,
        workload_logic_hash: COMPRESSION_LOGIC,
        input: COMPRESSION_INPUT.to_vec(),
        output: encoder.finish().expect("finish gzip"),
    }
}

#[cfg(not(test))]
fn sleep50() -> WorkloadResult {
    thread::sleep(Duration::from_millis(50));
    WorkloadResult {
        workload_id: SLEEP_ID,
        workload_logic_hash: SLEEP_LOGIC,
        input: SLEEP_INPUT.to_vec(),
        output: SLEEP_OUTPUT.to_vec(),
    }
}

#[cfg(test)]
fn sleep50() -> WorkloadResult {
    WorkloadResult {
        workload_id: SLEEP_ID,
        workload_logic_hash: SLEEP_LOGIC,
        input: SLEEP_INPUT.to_vec(),
        output: SLEEP_OUTPUT.to_vec(),
    }
}

fn run_workload(code: char) -> Result<WorkloadResult, &'static str> {
    match code {
        'd' => Ok(dynamic_html()),
        'g' => Ok(compression()),
        's' => Ok(sleep50()),
        _ => Err("unsupported workload code"),
    }
}

fn result_json(command: &Command, request_payload: &[u8], result: &WorkloadResult) -> String {
    let input_sha256 = hex(Sha256::digest(&result.input).as_slice());
    let output_sha256 = hex(Sha256::digest(&result.output).as_slice());
    let request_sha256 = hex(Sha256::digest(request_payload).as_slice());
    let mut output = format!(
        "{{\"schema_version\":\"c5-asyncs-result-v1\",\"suite_id\":\"{}\",\"workload_id\":\"{}\",\"workload_logic_hash\":\"{}\",\"phase\":\"{}\",\"logical_request_id\":\"{}\",\"attempt_id\":\"1\",\"ordinal\":{},\"application_input_bytes\":{},\"application_input_sha256\":\"{}\",\"application_output_bytes\":{},\"application_output_sha256\":\"{}\",\"workload_input_consumed\":true,\"request_payload_bytes\":{},\"request_payload_sha256\":\"{}\",\"request_payload_consumed\":true,\"full_output_included\":{}",
        SUITE_ID,
        result.workload_id,
        result.workload_logic_hash,
        command.phase,
        command.logical_request_id,
        command.ordinal,
        result.input.len(),
        input_sha256,
        result.output.len(),
        output_sha256,
        request_payload.len(),
        request_sha256,
        if command.phase == "correctness_probe" { "true" } else { "false" },
    );
    if command.phase == "correctness_probe" {
        output.push_str(",\"output_b64\":\"");
        output.push_str(&encode_base64(&result.output));
        output.push('"');
    }
    output.push('}');
    output
}

#[cfg(not(test))]
fn main() {
    let input_b64 = env::args().nth(1).expect("base64 C5 command argv");
    let request_payload = decode_base64(&input_b64).expect("valid C5 command base64");
    let command = parse_command(&request_payload).expect("valid C5 command");
    unsafe { c1_workload_tsc_begin() };
    let result = run_workload(command.workload_code).expect("supported C5 workload");
    unsafe { c1_workload_tsc_end() };
    let output = result_json(&command, &request_payload, &result);
    let status = unsafe { c1_workload_set_output(output.as_ptr(), output.len()) };
    assert_eq!(status, 0, "publish C5 output");
}

#[cfg(test)]
fn main() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_dynamic_html_matches_shared_expected_output() {
        let result = dynamic_html();
        assert_eq!(result.input.len(), 436);
        assert_eq!(
            hex(Sha256::digest(&result.input).as_slice()),
            "624e204f2a3e8409d707cec0a753b28e9ef86c5d6b61e80b3f9dce5f65b565e4"
        );
        assert_eq!(result.output, DYNAMIC_EXPECTED);
    }

    #[test]
    fn fixed_compression_consumes_shared_random_input() {
        let result = compression();
        assert_eq!(result.input.len(), 262_144);
        assert_eq!(
            hex(Sha256::digest(&result.input).as_slice()),
            "04f7209a1428aceb9b838a3043af314defd245fab3da383edf7753f23133d184"
        );
        assert!(!result.output.is_empty());
    }

    #[test]
    fn sleep_output_and_compact_command_match_shared_contract() {
        let payload = br#"{"a":"17","o":17,"p":"m","s":"v1","w":"s"}"#;
        let command = parse_command(payload).unwrap();
        assert_eq!(command.logical_request_id, "17");
        assert_eq!(command.ordinal, 17);
        assert_eq!(command.phase, "measured");
        let result = sleep50();
        assert_eq!(result.output, SLEEP_OUTPUT);
        let output = result_json(&command, payload, &result);
        assert!(output.contains("\"full_output_included\":false"));
        assert!(!output.contains("output_b64"));
    }

    #[test]
    fn probe_includes_full_functional_output() {
        let payload = br#"{"a":"1","o":1,"p":"p","s":"v1","w":"d"}"#;
        let command = parse_command(payload).unwrap();
        let result = dynamic_html();
        let output = result_json(&command, payload, &result);
        assert!(output.contains("\"full_output_included\":true"));
        assert!(output.contains("\"output_b64\":"));
    }
}
