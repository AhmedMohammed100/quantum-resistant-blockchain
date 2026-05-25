from __future__ import annotations

from dataclasses import dataclass
import importlib
import importlib.util
import platform
import sys


@dataclass(frozen=True)
class NativeCryptoTarget:
    target_id: str
    boundary: str
    implementation_language: str
    purpose: str
    package: str
    required_for_production: bool


NATIVE_CRYPTO_TARGETS: tuple[NativeCryptoTarget, ...] = (
    NativeCryptoTarget(
        target_id="rust_signer_worker_v1",
        boundary="wallet_signing",
        implementation_language="rust",
        purpose="memory-safe signer worker for ML-DSA/Falcon/SPHINCS+/stateful hash adapters",
        package="qr_chain_native_signer",
        required_for_production=True,
    ),
    NativeCryptoTarget(
        target_id="c_liboqs_runtime_v1",
        boundary="pq_algorithm_runtime",
        implementation_language="c",
        purpose="audited liboqs-backed standardized and candidate PQ algorithms",
        package="oqs",
        required_for_production=True,
    ),
    NativeCryptoTarget(
        target_id="rust_verify_pool_v1",
        boundary="consensus_verification",
        implementation_language="rust",
        purpose="parallel signature verification workers for mempool and block validation",
        package="qr_chain_native_verify",
        required_for_production=False,
    ),
)


def native_crypto_boundary_report() -> dict[str, object]:
    targets: list[dict[str, object]] = []
    missing_required: list[str] = []
    for target in NATIVE_CRYPTO_TARGETS:
        available = importlib.util.find_spec(target.package) is not None
        target_info: dict[str, object] = {}
        if available:
            try:
                module = importlib.import_module(target.package)
                backend_info = getattr(module, "backend_info", None)
                if callable(backend_info):
                    info = backend_info()
                    if isinstance(info, dict):
                        target_info = info
            except Exception as error:
                target_info = {"probe_error": str(error)}
        production_ready = available and (
            target.package != "qr_chain_native_signer" or bool(target_info.get("native_extension_loaded", False))
        )
        if target.required_for_production and not production_ready:
            missing_required.append(target.target_id)
        targets.append(
            {
                "target_id": target.target_id,
                "boundary": target.boundary,
                "implementation_language": target.implementation_language,
                "purpose": target.purpose,
                "package": target.package,
                "available": available,
                "production_ready": production_ready,
                "required_for_production": target.required_for_production,
                "details": target_info,
            }
        )
    return {
        "native_crypto_status": "ready_for_binding" if not missing_required else "python_orchestration_with_missing_native_targets",
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "targets": targets,
        "missing_required_targets": missing_required,
        "recommended_path": [
            "keep consensus and wallet signing separated",
            "bind Rust signer workers to vetted C/Rust PQ libraries",
            "run consensus verification through a worker pool boundary",
            "pin native runtime versions in release provenance",
        ],
    }
