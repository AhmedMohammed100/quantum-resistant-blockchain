# qr_chain_native_signer

This crate is the native Rust boundary for QBC post-quantum signing and verification.

Current status:

- `deterministic-test-backend` defines the first native API shape for tests and integration.
- `liboqs` is reserved for the audited runtime binding path.
- `python` exposes the crate as a Python extension through PyO3.

The deterministic backend is not cryptographic security. It exists only to stabilize the native ABI and integration contract before wiring vetted ML-DSA/Falcon/SPHINCS+/XMSS/LMS libraries.

Expected build path once Rust is installed:

```powershell
cargo test --manifest-path crates/qr_chain_native_signer/Cargo.toml
cargo build --manifest-path crates/qr_chain_native_signer/Cargo.toml --features deterministic-test-backend
cargo build --manifest-path crates/qr_chain_native_signer/Cargo.toml --features "python liboqs"
```
