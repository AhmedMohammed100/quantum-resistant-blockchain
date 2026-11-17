#![no_main]

use libfuzzer_sys::fuzz_target;
use native_signer::{generate_oqs_keypair, sign_oqs, verify_native_batch_json};
use std::sync::OnceLock;

const BASELINE_MESSAGE: &[u8] = b"QBC native liboqs FFI fuzz baseline v1";

struct Baseline {
    public_key_hex: String,
    signature_hex: String,
}

static BASELINE: OnceLock<Result<Baseline, String>> = OnceLock::new();

fn encode_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("odd hex length".to_string());
    }
    let mut result = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex".to_string())?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex".to_string())?;
        result.push(((hi << 4) | lo) as u8);
    }
    Ok(result)
}

fn make_request(
    message: &[u8],
    public_key_hex: &str,
    signature_hex: &str,
    algorithm: &str,
) -> String {
    format!(
        r#"{{"max_workers":1,"items":[{{"input_index":0,"message_hex":"{}","public_key":{{"public_key":"{}","mode":"liboqs","algorithm":"{}"}},"signature":{{"signature":"{}"}}}}]}}"#,
        encode_hex(message),
        public_key_hex,
        algorithm,
        signature_hex,
    )
}

fn baseline() -> Result<&'static Baseline, String> {
    let result = BASELINE.get_or_init(|| {
        let (public_key_hex, secret_key_hex) = generate_oqs_keypair("ML-DSA-65")?;
        let signature_hex = sign_oqs("ML-DSA-65", &secret_key_hex, BASELINE_MESSAGE)?;
        let request = make_request(
            BASELINE_MESSAGE,
            &public_key_hex,
            &signature_hex,
            "ML-DSA-65",
        );
        let response = verify_native_batch_json(&request)?;
        if !response.contains(r#"\"verified\":true"#) {
            return Err("real liboqs baseline signature failed native batch verification".to_string());
        }
        Ok(Baseline {
            public_key_hex,
            signature_hex,
        })
    });
    result.as_ref().map_err(Clone::clone)
}
fuzz_target!(|data: &[u8]| {
    let baseline = baseline().expect("real liboqs baseline initialization must succeed");

    // Exercise the actual batch parser with raw fuzz bytes as well as the
    // structured request that reaches QBC's checked Rust-to-C verification path.
    let raw = String::from_utf8_lossy(data);
    let _ = verify_native_batch_json(&raw);

    let mut public_key = match decode_hex(&baseline.public_key_hex) {
        Ok(value) => value,
        Err(_) => return,
    };
    let mut signature = match decode_hex(&baseline.signature_hex) {
        Ok(value) => value,
        Err(_) => return,
    };
    let mut message = BASELINE_MESSAGE.to_vec();
    let mut algorithm = "ML-DSA-65";

    let selector = data.first().copied().unwrap_or(0) % 8;
    let payload = data.get(1..).unwrap_or_default();
    match selector {
        // Fixed-size corruption passes the wrapper's size checks and reaches
        // OQS_SIG_verify with attacker-controlled bytes.
        0 => {
            if !signature.is_empty() && !payload.is_empty() {
                let index = usize::from(payload[0]) % signature.len();
                signature[index] ^= payload.last().copied().unwrap_or(1) | 1;
            }
        }
        1 => {
            if !public_key.is_empty() && !payload.is_empty() {
                let index = usize::from(payload[0]) % public_key.len();
                public_key[index] ^= payload.last().copied().unwrap_or(1) | 1;
            }
        }
        // Exercise exact-length rejection before the C verifier.
        2 => {
            let remove = 1 + payload.first().copied().unwrap_or(0) as usize % 31;
            signature.truncate(signature.len().saturating_sub(remove));
        }
        3 => {
            message.extend_from_slice(payload);
            if message.len() > 4096 {
                message.truncate(4096);
            }
        }
        4 => {
            if !public_key.is_empty() {
                public_key.pop();
            }
        }
        5 => {
            signature.clear();
            signature.push(0xff);
        }
        6 => algorithm = "ML-DSA-44",
        _ => algorithm = "not-a-liboqs-algorithm",
    }

    let request = make_request(
        &message,
        &encode_hex(&public_key),
        &encode_hex(&signature),
        algorithm,
    );
    let _ = verify_native_batch_json(&request);
});
