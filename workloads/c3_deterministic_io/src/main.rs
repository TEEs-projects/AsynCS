use sha2::{Digest, Sha256};
#[cfg(not(test))]
use std::env;

#[cfg(not(test))]
#[link(wasm_import_module = "env")]
extern "C" {
    fn c1_workload_tsc_begin() -> u64;
    fn c1_workload_tsc_end() -> u64;
    fn c1_workload_set_output(data: *const u8, len: usize) -> i32;
}

const WORKLOAD_ID: &str = "c3-deterministic-io-v1";
const WORKLOAD_LOGIC_HASH: &str = "rust-base64-decode-identity-sha256-base64-encode-v1";
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
        let c = if pad == 2 { 0 } else { decode_digit(chunk[2])? as u32 };
        let d = if pad > 0 { 0 } else { decode_digit(chunk[3])? as u32 };
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

fn deterministic_io(input_b64: &str) -> Result<String, &'static str> {
    let input = decode_base64(input_b64)?;
    let output = input.clone();
    let input_sha256 = hex(Sha256::digest(&input).as_slice());
    let output_sha256 = hex(Sha256::digest(&output).as_slice());
    let output_b64 = encode_base64(&output);
    Ok(format!(
        "{{\"schema_version\":\"c3-deterministic-io-result-v1\",\"workload_id\":\"{}\",\"workload_logic_hash\":\"{}\",\"workload_kind\":\"deterministic_io_identity\",\"workload_input_bytes\":{},\"workload_input_sha256\":\"{}\",\"workload_output_bytes\":{},\"workload_output_sha256\":\"{}\",\"workload_input_consumed\":true,\"output_b64\":\"{}\"}}",
        WORKLOAD_ID,
        WORKLOAD_LOGIC_HASH,
        input.len(),
        input_sha256,
        output.len(),
        output_sha256,
        output_b64,
    ))
}

#[cfg(not(test))]
fn main() {
    let input_b64 = env::args().nth(1).expect("base64 input argv");
    unsafe { c1_workload_tsc_begin() };
    let output = deterministic_io(&input_b64).expect("deterministic I/O input");
    unsafe { c1_workload_tsc_end() };
    let status = unsafe { c1_workload_set_output(output.as_ptr(), output.len()) };
    assert_eq!(status, 0, "publish deterministic I/O output");
}

#[cfg(test)]
fn main() {}

#[cfg(test)]
mod tests {
    use super::{decode_base64, deterministic_io, encode_base64};
    use sha2::{Digest, Sha256};

    fn fixture(size: usize) -> Vec<u8> {
        (0..size)
            .map(|index| ((index as u64 * 1_103_515_245 + 12_345) & 0xff) as u8)
            .collect()
    }

    #[test]
    fn base64_round_trip_covers_probe_and_medium_sizes() {
        for size in [1_024, 65_536] {
            let bytes = fixture(size);
            assert_eq!(decode_base64(&encode_base64(&bytes)).unwrap(), bytes);
        }
    }

    #[test]
    fn result_contains_the_complete_identity_output() {
        let bytes = fixture(65_536);
        let output_b64 = encode_base64(&bytes);
        let result = deterministic_io(&output_b64).unwrap();
        let expected_hash = format!("{:x}", Sha256::digest(&bytes));
        assert!(result.contains("\"workload_input_bytes\":65536"));
        assert!(result.contains("\"workload_output_bytes\":65536"));
        assert!(result.contains(&format!("\"workload_input_sha256\":\"{}\"", expected_hash)));
        assert!(result.contains(&format!("\"workload_output_sha256\":\"{}\"", expected_hash)));
        assert!(result.contains(&format!("\"output_b64\":\"{}\"", output_b64)));
    }
}
