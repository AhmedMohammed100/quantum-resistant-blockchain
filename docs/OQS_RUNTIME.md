# OQS Runtime Pin

The `mldsa65_oqs_v1` signature provider is the project's first live Open Quantum Safe runtime path. It targets `ML-DSA-65`, the NIST-standardized ML-DSA family derived from CRYSTALS-Dilithium.

## Pinned Target

- Python package: `liboqs-python==0.14.1`
- Native runtime target: `liboqs 0.15.0`
- Provider id: `mldsa65_oqs_v1`
- Mechanism: `ML-DSA-65`

Install or refresh the pinned runtime:

```powershell
$env:PYOQS_VERSION = "0.15.0"
python -m pip install --upgrade --force-reinstall --requirement requirements-oqs.txt
```

Verify the runtime:

```powershell
python -c "import oqs; print([m for m in oqs.get_enabled_sig_mechanisms() if 'ML-DSA' in m or 'Dilithium' in m or 'Falcon' in m])"
python -c "from qr_blockchain.crypto import get_signature_provider; p=get_signature_provider('mldsa65_oqs_v1'); kp=p.generate_keypair(); pub,sig=p.sign(kp,b'probe'); print(p.verify(b'probe', sig, pub)); print(p.backend_status()['selected_mechanism'])"
```

Expected result:

```text
True
ML-DSA-65
```

## Provider Selection

The default provider policy can prefer this runtime when it is available:

```powershell
$env:QR_CHAIN_DEFAULT_SIGNATURE_PROVIDER = "mldsa65_oqs_v1"
$env:QR_CHAIN_PREFERRED_SIGNATURE_PROVIDERS = "mldsa65_oqs_v1,sphincsplus_v1,lms_nist_v1,xmss_nist_v1,xmss_merkle_lamport_v1"
```

If `ML-DSA-65` is unavailable, the provider reports a precise dependency or mechanism error instead of silently falling back.

## Sources

- Open Quantum Safe `liboqs-python`: https://github.com/open-quantum-safe/liboqs-python
- Open Quantum Safe ML-DSA notes: https://openquantumsafe.org/liboqs/algorithms/sig/ml-dsa.html
- NIST FIPS 204: https://csrc.nist.gov/pubs/fips/204/final
