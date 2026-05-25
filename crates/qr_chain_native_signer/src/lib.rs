#[cfg(feature = "python")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "liboqs")]
use std::ffi::{CStr, CString};
#[cfg(feature = "liboqs")]
use std::os::raw::{c_char, c_int};

pub const API_VERSION: u32 = 1;
pub const BACKEND_NAME: &str = "qr_chain_native_signer";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeKeypair {
    pub public_key: String,
    pub secret_key: String,
}

fn fnv1a64(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

pub fn backend_mode() -> &'static str {
    #[cfg(feature = "liboqs")]
    {
        return "liboqs";
    }
    #[cfg(not(feature = "liboqs"))]
    {
        "deterministic_test"
    }
}

pub fn generate_test_keypair(seed: &str) -> NativeKeypair {
    let secret_key = format!("native-test-secret-{}", fnv1a64(seed.as_bytes()));
    let public_key = format!("native-test-public-{}", fnv1a64(secret_key.as_bytes()));
    NativeKeypair {
        public_key,
        secret_key,
    }
}

pub fn sign_test(public_key: &str, message: &[u8]) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(public_key.as_bytes());
    payload.extend_from_slice(b":");
    payload.extend_from_slice(message);
    format!("native-test-signature-{}", fnv1a64(&payload))
}

pub fn verify_test(public_key: &str, message: &[u8], signature: &str) -> bool {
    sign_test(public_key, message) == signature
}

#[derive(Debug, Deserialize)]
struct VerificationBatchRequest {
    items: Vec<VerificationBatchItem>,
    max_workers: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct VerificationBatchItem {
    input_index: usize,
    message_hex: String,
    public_key: Value,
    signature: Value,
}

#[derive(Debug, Serialize)]
struct VerificationBatchResponse {
    worker: &'static str,
    checked_inputs: usize,
    worker_count: usize,
    results: Vec<VerificationBatchItemResult>,
}

#[derive(Debug, Serialize)]
struct VerificationBatchItemResult {
    input_index: usize,
    verified: bool,
    failure: String,
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex value must have an even length".to_string());
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for index in (0..bytes.len()).step_by(2) {
        let hi = (bytes[index] as char)
            .to_digit(16)
            .ok_or_else(|| "hex value contains a non-hex character".to_string())?;
        let lo = (bytes[index + 1] as char)
            .to_digit(16)
            .ok_or_else(|| "hex value contains a non-hex character".to_string())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

fn json_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field: {field}"))
}

fn verify_batch_item(item: &VerificationBatchItem) -> VerificationBatchItemResult {
    match verify_batch_item_inner(item) {
        Ok(true) => VerificationBatchItemResult {
            input_index: item.input_index,
            verified: true,
            failure: String::new(),
        },
        Ok(false) => VerificationBatchItemResult {
            input_index: item.input_index,
            verified: false,
            failure: format!("input {} native signature verification failed", item.input_index),
        },
        Err(error) => VerificationBatchItemResult {
            input_index: item.input_index,
            verified: false,
            failure: format!("input {} native verification error: {error}", item.input_index),
        },
    }
}

fn verify_batch_item_inner(item: &VerificationBatchItem) -> Result<bool, String> {
    let message = decode_hex(&item.message_hex)?;
    let public_key = json_string(&item.public_key, "public_key")?;
    let signature = json_string(&item.signature, "signature")?;
    let mode = item
        .public_key
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("deterministic_test");

    if mode == "liboqs" {
        let algorithm = item
            .public_key
            .get("algorithm")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("ML-DSA-65");
        verify_oqs(algorithm, public_key, &message, signature)
    } else {
        Ok(verify_test(public_key, &message, signature))
    }
}

pub fn verify_native_batch_json(request_json: &str) -> Result<String, String> {
    let request: VerificationBatchRequest =
        serde_json::from_str(request_json).map_err(|error| format!("invalid verification batch JSON: {error}"))?;
    let checked_inputs = request.items.len();
    let requested_workers = request
        .max_workers
        .unwrap_or_else(|| std::thread::available_parallelism().map(usize::from).unwrap_or(1));
    let worker_count = requested_workers.clamp(1, checked_inputs.max(1));

    let mut results = Vec::with_capacity(checked_inputs);
    if checked_inputs == 0 {
        let response = VerificationBatchResponse {
            worker: "rust_native_batch_v1",
            checked_inputs,
            worker_count: 0,
            results,
        };
        return serde_json::to_string(&response).map_err(|error| error.to_string());
    }

    if worker_count == 1 {
        results.extend(request.items.iter().map(verify_batch_item));
    } else {
        let chunk_size = (checked_inputs + worker_count - 1) / worker_count;
        std::thread::scope(|scope| -> Result<(), String> {
            let handles = request
                .items
                .chunks(chunk_size)
                .map(|chunk| scope.spawn(move || chunk.iter().map(verify_batch_item).collect::<Vec<_>>()))
                .collect::<Vec<_>>();
            for handle in handles {
                let mut batch_results = handle
                    .join()
                    .map_err(|_| "native verification worker panicked".to_string())?;
                results.append(&mut batch_results);
            }
            Ok(())
        })?;
        results.sort_by_key(|item| item.input_index);
    }

    let response = VerificationBatchResponse {
        worker: "rust_native_batch_v1",
        checked_inputs,
        worker_count,
        results,
    };
    serde_json::to_string(&response).map_err(|error| error.to_string())
}

#[cfg(feature = "liboqs")]
#[repr(C)]
struct OqsSig {
    method_name: *const c_char,
    alg_version: *const c_char,
    claimed_nist_level: u8,
    euf_cma: bool,
    suf_cma: bool,
    sig_with_ctx_support: bool,
    length_public_key: usize,
    length_secret_key: usize,
    length_signature: usize,
}

#[cfg(feature = "liboqs")]
#[link(name = "oqs")]
extern "C" {
    fn OQS_init();
    fn OQS_version() -> *const c_char;
    fn OQS_SIG_new(method_name: *const c_char) -> *mut OqsSig;
    fn OQS_SIG_free(sig: *mut OqsSig);
    fn OQS_SIG_keypair(sig: *const OqsSig, public_key: *mut u8, secret_key: *mut u8) -> c_int;
    fn OQS_SIG_sign(
        sig: *const OqsSig,
        signature: *mut u8,
        signature_len: *mut usize,
        message: *const u8,
        message_len: usize,
        secret_key: *const u8,
    ) -> c_int;
    fn OQS_SIG_verify(
        sig: *const OqsSig,
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
    ) -> c_int;
}

#[cfg(feature = "liboqs")]
struct SigHandle(*mut OqsSig);

#[cfg(feature = "liboqs")]
impl SigHandle {
    fn new(name: &str) -> Result<Self, String> {
        unsafe { OQS_init() };
        let method = CString::new(oqs_algorithm_name(name)?).map_err(|error| error.to_string())?;
        let ptr = unsafe { OQS_SIG_new(method.as_ptr()) };
        if ptr.is_null() {
            return Err(format!("liboqs signature algorithm is unavailable: {name}"));
        }
        Ok(Self(ptr))
    }

    fn sig(&self) -> &OqsSig {
        unsafe { &*self.0 }
    }
}

#[cfg(feature = "liboqs")]
impl Drop for SigHandle {
    fn drop(&mut self) {
        unsafe { OQS_SIG_free(self.0) };
    }
}

#[cfg(feature = "liboqs")]
fn oqs_algorithm_name(name: &str) -> Result<&'static str, String> {
    let normalized = name
        .trim()
        .to_ascii_lowercase()
        .replace(['_', '-', '+'], "")
        .replace("simple", "");
    match normalized.as_str() {
        "mldsa44" | "dilithium2" => Ok("ML-DSA-44"),
        "mldsa65" | "dilithium3" => Ok("ML-DSA-65"),
        "mldsa87" | "dilithium5" => Ok("ML-DSA-87"),
        "falcon512" => Ok("Falcon-512"),
        "falcon1024" => Ok("Falcon-1024"),
        "sphincsshake128f" | "sphincsplusshake128f" => Ok("SPHINCS+-SHAKE-128f-simple"),
        "sphincsshake128s" | "sphincsplusshake128s" => Ok("SPHINCS+-SHAKE-128s-simple"),
        "sphincsshake192f" | "sphincsplusshake192f" => Ok("SPHINCS+-SHAKE-192f-simple"),
        "sphincsshake192s" | "sphincsplusshake192s" => Ok("SPHINCS+-SHAKE-192s-simple"),
        "sphincsshake256f" | "sphincsplusshake256f" => Ok("SPHINCS+-SHAKE-256f-simple"),
        "sphincsshake256s" | "sphincsplusshake256s" => Ok("SPHINCS+-SHAKE-256s-simple"),
        "sphincssha2128f" | "sphincsplussha2128f" => Ok("SPHINCS+-SHA2-128f-simple"),
        "sphincssha2128s" | "sphincsplussha2128s" => Ok("SPHINCS+-SHA2-128s-simple"),
        "sphincssha2192f" | "sphincsplussha2192f" => Ok("SPHINCS+-SHA2-192f-simple"),
        "sphincssha2192s" | "sphincsplussha2192s" => Ok("SPHINCS+-SHA2-192s-simple"),
        "sphincssha2256f" | "sphincsplussha2256f" => Ok("SPHINCS+-SHA2-256f-simple"),
        "sphincssha2256s" | "sphincsplussha2256s" => Ok("SPHINCS+-SHA2-256s-simple"),
        _ => Err(format!("unsupported liboqs signature algorithm: {name}")),
    }
}

#[cfg(feature = "liboqs")]
pub fn oqs_runtime_version() -> String {
    let ptr = unsafe { OQS_version() };
    if ptr.is_null() {
        return "unknown".to_string();
    }
    unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
}

#[cfg(feature = "liboqs")]
pub fn generate_oqs_keypair(algorithm_name: &str) -> Result<(String, String), String> {
    let handle = SigHandle::new(algorithm_name)?;
    let sig = handle.sig();
    let mut public_key = vec![0_u8; sig.length_public_key];
    let mut secret_key = vec![0_u8; sig.length_secret_key];
    let status = unsafe { OQS_SIG_keypair(handle.0, public_key.as_mut_ptr(), secret_key.as_mut_ptr()) };
    if status != 0 {
        return Err("liboqs OQS_SIG_keypair failed".to_string());
    }
    Ok((encode_hex(&public_key), encode_hex(&secret_key)))
}

#[cfg(feature = "liboqs")]
pub fn sign_oqs(algorithm_name: &str, secret_key_hex: &str, message: &[u8]) -> Result<String, String> {
    let handle = SigHandle::new(algorithm_name)?;
    let sig = handle.sig();
    let secret_key = decode_hex(secret_key_hex)?;
    if secret_key.len() != sig.length_secret_key {
        return Err("invalid liboqs secret key length".to_string());
    }
    let mut signature = vec![0_u8; sig.length_signature];
    let mut signature_len = 0_usize;
    let status = unsafe {
        OQS_SIG_sign(
            handle.0,
            signature.as_mut_ptr(),
            &mut signature_len,
            message.as_ptr(),
            message.len(),
            secret_key.as_ptr(),
        )
    };
    if status != 0 {
        return Err("liboqs OQS_SIG_sign failed".to_string());
    }
    signature.truncate(signature_len);
    Ok(encode_hex(&signature))
}

#[cfg(feature = "liboqs")]
pub fn verify_oqs(
    algorithm_name: &str,
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<bool, String> {
    let handle = SigHandle::new(algorithm_name)?;
    let sig = handle.sig();
    let public_key = decode_hex(public_key_hex)?;
    let signature = decode_hex(signature_hex)?;
    if public_key.len() != sig.length_public_key {
        return Err("invalid liboqs public key length".to_string());
    }
    Ok(unsafe {
        OQS_SIG_verify(
            handle.0,
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
            public_key.as_ptr(),
        )
    } == 0)
}

#[cfg(not(feature = "liboqs"))]
pub fn generate_oqs_keypair(_algorithm_name: &str) -> Result<(String, String), String> {
    Err("liboqs feature is not enabled in qr_chain_native_signer".to_string())
}

#[cfg(not(feature = "liboqs"))]
pub fn sign_oqs(_algorithm_name: &str, _secret_key_hex: &str, _message: &[u8]) -> Result<String, String> {
    Err("liboqs feature is not enabled in qr_chain_native_signer".to_string())
}

#[cfg(not(feature = "liboqs"))]
pub fn verify_oqs(
    _algorithm_name: &str,
    _public_key_hex: &str,
    _message: &[u8],
    _signature_hex: &str,
) -> Result<bool, String> {
    Err("liboqs feature is not enabled in qr_chain_native_signer".to_string())
}

#[cfg(feature = "python")]
#[pyfunction]
fn backend_info_py() -> PyResult<String> {
    #[cfg(feature = "liboqs")]
    let oqs_version = oqs_runtime_version();
    #[cfg(not(feature = "liboqs"))]
    let oqs_version = "unavailable".to_string();
    Ok(format!(
        "{{\"backend_name\":\"{}\",\"api_version\":{},\"backend_mode\":\"{}\",\"oqs_runtime_version\":\"{}\"}}",
        BACKEND_NAME,
        API_VERSION,
        backend_mode(),
        oqs_version
    ))
}

#[cfg(feature = "python")]
#[pyfunction]
fn generate_test_keypair_py(seed: &str) -> PyResult<(String, String)> {
    let keypair = generate_test_keypair(seed);
    Ok((keypair.public_key, keypair.secret_key))
}

#[cfg(feature = "python")]
#[pyfunction]
fn sign_test_py(public_key: &str, message: &[u8]) -> PyResult<String> {
    Ok(sign_test(public_key, message))
}

#[cfg(feature = "python")]
#[pyfunction]
fn verify_test_py(public_key: &str, message: &[u8], signature: &str) -> PyResult<bool> {
    Ok(verify_test(public_key, message, signature))
}

#[cfg(feature = "python")]
#[pyfunction]
fn generate_oqs_keypair_py(algorithm_name: &str) -> PyResult<(String, String)> {
    generate_oqs_keypair(algorithm_name).map_err(pyo3::exceptions::PyRuntimeError::new_err)
}

#[cfg(feature = "python")]
#[pyfunction]
fn sign_oqs_py(algorithm_name: &str, secret_key_hex: &str, message: &[u8]) -> PyResult<String> {
    sign_oqs(algorithm_name, secret_key_hex, message).map_err(pyo3::exceptions::PyRuntimeError::new_err)
}

#[cfg(feature = "python")]
#[pyfunction]
fn verify_oqs_py(
    algorithm_name: &str,
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> PyResult<bool> {
    verify_oqs(algorithm_name, public_key_hex, message, signature_hex)
        .map_err(pyo3::exceptions::PyRuntimeError::new_err)
}

#[cfg(feature = "python")]
#[pyfunction]
fn verify_native_batch_py(py: Python<'_>, request_json: &str) -> PyResult<String> {
    py.allow_threads(|| verify_native_batch_json(request_json))
        .map_err(pyo3::exceptions::PyRuntimeError::new_err)
}

#[cfg(feature = "python")]
#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(backend_info_py, module)?)?;
    module.add_function(wrap_pyfunction!(generate_test_keypair_py, module)?)?;
    module.add_function(wrap_pyfunction!(sign_test_py, module)?)?;
    module.add_function(wrap_pyfunction!(verify_test_py, module)?)?;
    module.add_function(wrap_pyfunction!(generate_oqs_keypair_py, module)?)?;
    module.add_function(wrap_pyfunction!(sign_oqs_py, module)?)?;
    module.add_function(wrap_pyfunction!(verify_oqs_py, module)?)?;
    module.add_function(wrap_pyfunction!(verify_native_batch_py, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_test_signature_round_trips() {
        let keypair = generate_test_keypair("seed");
        let signature = sign_test(&keypair.public_key, b"hello");
        assert!(verify_test(&keypair.public_key, b"hello", &signature));
        assert!(!verify_test(&keypair.public_key, b"tampered", &signature));
    }

    #[test]
    fn deterministic_batch_verification_reports_per_input_results() {
        let keypair = generate_test_keypair("seed");
        let signature = sign_test(&keypair.public_key, b"hello");
        let request = serde_json::json!({
            "max_workers": 2,
            "items": [
                {
                    "input_index": 0,
                    "message_hex": encode_hex(b"hello"),
                    "public_key": {
                        "scheme_id": "native_test_pq_v1",
                        "public_key": keypair.public_key,
                        "mode": "deterministic_test"
                    },
                    "signature": {
                        "scheme_id": "native_test_pq_v1",
                        "signature": signature,
                        "mode": "rust_extension"
                    }
                },
                {
                    "input_index": 1,
                    "message_hex": encode_hex(b"tampered"),
                    "public_key": {
                        "scheme_id": "native_test_pq_v1",
                        "public_key": keypair.public_key,
                        "mode": "deterministic_test"
                    },
                    "signature": {
                        "scheme_id": "native_test_pq_v1",
                        "signature": signature,
                        "mode": "rust_extension"
                    }
                }
            ]
        });

        let response = verify_native_batch_json(&request.to_string()).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["worker"], "rust_native_batch_v1");
        assert_eq!(parsed["checked_inputs"], 2);
        assert_eq!(parsed["results"][0]["verified"], true);
        assert_eq!(parsed["results"][1]["verified"], false);
    }
}
