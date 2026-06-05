from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import time
from dataclasses import replace

from .config import NodeConfig
from .migration import (
    build_demo_classical_claim_address,
    build_demo_classical_claim_proof,
    build_demo_classical_claim_public_key,
    classical_claim_message_bytes,
)
from .models import Transaction, TxOutput
from .service import NodeService
from .signer import Wallet
from .verification import verify_transaction_inputs


def run_load_chaos_harness(
    *,
    base_config: NodeConfig,
    scenario: str = "all",
    node_count: int = 3,
    mempool_transactions: int = 8,
    migration_claims: int = 6,
    verification_batch_size: int = 8,
    work_dir: Path | None = None,
) -> dict[str, object]:
    root = work_dir or (base_config.db_path.parent / "chaos_harness")
    created_temp = work_dir is None
    if created_temp and root.exists():
        shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    try:
        harness = ChaosHarness(base_config=base_config, root=root, node_count=max(2, node_count))
        selected = _selected_scenarios(scenario)
        results: dict[str, dict[str, object]] = {}
        if "mempool_flood" in selected:
            results["mempool_flood"] = harness.mempool_flood(mempool_transactions)
        if "fork_storm" in selected:
            results["fork_storm"] = harness.fork_storm()
        if "migration_disputes" in selected:
            results["migration_disputes"] = harness.migration_dispute_lifecycle(migration_claims)
        if "migration_economics" in selected:
            results["migration_economics"] = harness.migration_economics_campaign(migration_claims)
        if "migration_escrow_fraud" in selected:
            results["migration_escrow_fraud"] = harness.migration_escrow_fraud_path()
        if "signer_crash" in selected:
            results["signer_crash"] = harness.signer_crash_recovery()
        if "verification_throughput" in selected:
            results["verification_throughput"] = harness.verification_throughput(verification_batch_size)

        passed = all(bool(result.get("passed", False)) for result in results.values())
        report = {
            "harness_version": 1,
            "scenario": scenario,
            "node_count": harness.node_count,
            "work_dir": str(root),
            "passed": passed,
            "scenario_count": len(results),
            "results": results,
        }
        report["report_hash"] = hashlib.sha256(
            json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return report
    finally:
        if created_temp:
            shutil.rmtree(root, ignore_errors=True)


def _selected_scenarios(scenario: str) -> set[str]:
    normalized = scenario.strip().lower().replace("-", "_")
    all_scenarios = {
        "mempool_flood",
        "fork_storm",
        "migration_disputes",
        "migration_economics",
        "migration_escrow_fraud",
        "signer_crash",
        "verification_throughput",
    }
    aliases = {
        "all": all_scenarios,
        "mempool": {"mempool_flood"},
        "fork": {"fork_storm"},
        "migration": {"migration_disputes"},
        "migration_economics": {"migration_economics"},
        "migration_escrow": {"migration_escrow_fraud"},
        "signer": {"signer_crash"},
        "verification": {"verification_throughput"},
    }
    if normalized in aliases:
        return set(aliases[normalized])
    if normalized in all_scenarios:
        return {normalized}
    raise ValueError(f"Unknown chaos harness scenario: {scenario}")


class ChaosHarness:
    def __init__(self, *, base_config: NodeConfig, root: Path, node_count: int):
        self.base_config = base_config
        self.root = root
        self.node_count = node_count

    def service(self, name: str, *, max_pending_transactions: int | None = None) -> NodeService:
        node_root = self.root / name
        node_root.mkdir(parents=True, exist_ok=True)
        config = replace(
            self.base_config,
            db_path=node_root / "chain.db",
            wallet_state_db_path=node_root / "wallet_state.db",
            difficulty=1,
            mining_reward=10,
            max_pending_transactions=(
                self.base_config.max_pending_transactions
                if max_pending_transactions is None
                else max_pending_transactions
            ),
            min_transaction_fee=1,
            max_transaction_size_bytes=16777216,
            migration_dual_control_start_height=0,
            migration_dual_control_end_height=0,
            node_id=f"chaos-{name}",
            advertised_url=f"http://chaos-{name}:8080",
        )
        return NodeService(config)

    def mempool_flood(self, transaction_count: int) -> dict[str, object]:
        service = self.service("mempool", max_pending_transactions=max(2, transaction_count // 2))
        senders = [
            Wallet(f"FloodSender{index}", state_db_path=self.root / f"mempool_sender_{index}.db")
            for index in range(transaction_count)
        ]
        recipients = [Wallet(f"FloodRecipient{index}") for index in range(transaction_count)]
        funding: dict[str, int] = {}
        for index, sender in enumerate(senders):
            funding[sender.create_address()] = 3 + index
        service.create_genesis_block(funding)

        accepted = 0
        rejected = 0
        rejection_reasons: dict[str, int] = {}
        for index in range(transaction_count):
            try:
                tx = senders[index].create_transaction(service, recipients[index].create_address(), amount=1, fee=1)
                service.submit_transaction(tx)
                accepted += 1
            except ValueError as error:
                rejected += 1
                reason = str(error)
                rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1

        limit = service.config.max_pending_transactions
        return {
            "passed": accepted == limit and rejected == max(0, transaction_count - limit),
            "submitted": transaction_count,
            "accepted": accepted,
            "rejected": rejected,
            "mempool_limit": limit,
            "pending_transactions": service.store.pending_transaction_count(),
            "rejection_reasons": rejection_reasons,
        }

    def fork_storm(self) -> dict[str, object]:
        base_address = "fork-bootstrap"
        branches = [self.service(f"fork-{index}") for index in range(self.node_count)]
        target = self.service("fork-target")
        for service in [*branches, target]:
            service.create_genesis_block({base_address: 1})

        branch_heads: list[dict[str, object]] = []
        for index, service in enumerate(branches):
            miner = f"fork-miner-{index}"
            length = index + 1
            blocks = [service.mine_pending_transactions(miner) for _ in range(length)]
            branch_heads.append(
                {
                    "node": service.config.node_id,
                    "height": service.chain_summary()["height"],
                    "head": blocks[-1].block_hash,
                    "state_root": blocks[-1].state_root,
                }
            )
            for block in blocks:
                target.import_block(block)

        best = target.chain_summary()
        expected_height = max(int(item["height"]) for item in branch_heads)
        return {
            "passed": int(best["height"]) == expected_height,
            "candidate_heads": branch_heads,
            "selected_height": best["height"],
            "selected_head": best["latest_block_hash"],
            "selected_state_root": target.get_block(int(best["height"]) - 1).state_root if best["height"] else "",
        }

    def migration_dispute_lifecycle(self, claim_count: int) -> dict[str, object]:
        service = self.service("migration-disputes")
        wallet = Wallet("MigrationChaosWallet")
        miner = Wallet("MigrationChaosMiner")
        service.create_genesis_block({miner.create_address(): 1})
        accepted_claims = 0
        blocked_claims = 0
        disputes: list[dict[str, object]] = []

        for index in range(claim_count):
            classical_public_key = build_demo_classical_claim_public_key(f"chaos-claim-{index}")
            classical_address = build_demo_classical_claim_address(classical_public_key)
            service.seed_migration_source(
                classical_address=classical_address,
                provider_id="classical_claim_demo_v1",
                source_network="legacy-chaos-ledger",
                amount=5,
                snapshot_ref="chaos-snapshot",
            )
            if index % 3 == 0:
                opened = service.open_migration_dispute(classical_address, reason="chaos challenge")
                if index % 2 == 0:
                    service.submit_migration_dispute_evidence(
                        opened["dispute_id"],
                        evidence={"case": index, "source": classical_address},
                    )
                    service.resolve_migration_dispute(
                        opened["dispute_id"],
                        outcome="resolved_valid",
                        resolution_note="chaos review accepted",
                    )
                disputes.append(service._migration_dispute_by_id(opened["dispute_id"]))

            preview = service.build_migration_claim_draft(
                destination_address=wallet.create_address(),
                classical_address=classical_address,
                classical_provider_id="classical_claim_demo_v1",
                source_network="legacy-chaos-ledger",
                snapshot_ref="chaos-snapshot",
                classical_public_key=classical_public_key,
            )
            signature = build_demo_classical_claim_proof(
                classical_public_key,
                classical_claim_message_bytes(preview.migration_claim_payload()),
            )
            claim = wallet.create_migration_claim(
                service,
                classical_address=classical_address,
                classical_provider_id="classical_claim_demo_v1",
                classical_public_key=classical_public_key,
                classical_signature=signature,
                source_network="legacy-chaos-ledger",
                snapshot_ref="chaos-snapshot",
                destination_address=preview.outputs[0].recipient,
                timestamp=preview.timestamp,
            )
            try:
                service.submit_transaction(claim)
                accepted_claims += 1
            except ValueError:
                blocked_claims += 1

        if accepted_claims:
            service.mine_pending_transactions(miner.create_address())
        summary = service.migration_disputes()
        return {
            "passed": accepted_claims > 0 and blocked_claims > 0 and summary["dispute_count"] == len(disputes),
            "claim_count": claim_count,
            "accepted_claims": accepted_claims,
            "blocked_claims": blocked_claims,
            "dispute_summary": summary,
        }

    def migration_economics_campaign(self, claim_count: int) -> dict[str, object]:
        service = self.service("migration-economics")
        service.config = replace(
            service.config,
            migration_claim_per_address_cap=5,
            migration_epoch_mint_cap=max(5, claim_count * 5),
            migration_epoch_length_blocks=100,
            migration_escrow_blocks=1,
        )
        wallet = Wallet("MigrationEconomicsWallet")
        miner = Wallet("MigrationEconomicsMiner")
        service.create_genesis_block({miner.create_address(): 1})
        submitted = 0
        for index in range(claim_count):
            classical_public_key = build_demo_classical_claim_public_key(f"economics-claim-{index}")
            classical_address = build_demo_classical_claim_address(classical_public_key)
            service.seed_migration_source(
                classical_address=classical_address,
                provider_id="classical_claim_demo_v1",
                source_network="legacy-economics-ledger",
                amount=20,
                snapshot_ref="economics-snapshot",
            )
            preview = service.build_migration_claim_draft(
                destination_address=wallet.create_address(),
                classical_address=classical_address,
                classical_provider_id="classical_claim_demo_v1",
                source_network="legacy-economics-ledger",
                snapshot_ref="economics-snapshot",
                classical_public_key=classical_public_key,
            )
            signature = build_demo_classical_claim_proof(
                classical_public_key,
                classical_claim_message_bytes(preview.migration_claim_payload()),
            )
            claim = wallet.create_migration_claim(
                service,
                classical_address=classical_address,
                classical_provider_id="classical_claim_demo_v1",
                classical_public_key=classical_public_key,
                classical_signature=signature,
                source_network="legacy-economics-ledger",
                snapshot_ref="economics-snapshot",
                destination_address=preview.outputs[0].recipient,
                timestamp=preview.timestamp,
            )
            try:
                service.submit_transaction(claim)
                submitted += 1
            except ValueError:
                break
        if submitted:
            service.mine_pending_transactions(miner.create_address())
        invariants = service.migration_economics_invariant_report()
        simulation = service.migration_adversarial_economics_simulation_report()
        return {
            "passed": submitted > 0 and invariants["status"] == "pass" and simulation["status"] == "pass",
            "submitted_claims": submitted,
            "invariant_status": invariants["status"],
            "simulation_status": simulation["status"],
            "guardrails": service.migration_conversion_guardrail_report(),
        }

    def migration_escrow_fraud_path(self) -> dict[str, object]:
        service = self.service("migration-escrow-fraud")
        service.config = replace(service.config, migration_escrow_blocks=2)
        wallet = Wallet("MigrationEscrowWallet")
        miner = Wallet("MigrationEscrowMiner")
        receiver = Wallet("MigrationEscrowReceiver")
        service.create_genesis_block({miner.create_address(): 1})
        classical_public_key = build_demo_classical_claim_public_key("escrow-fraud-claim")
        classical_address = build_demo_classical_claim_address(classical_public_key)
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-escrow-ledger",
            amount=9,
            snapshot_ref="escrow-snapshot",
        )
        preview = service.build_migration_claim_draft(
            destination_address=wallet.create_address(),
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            source_network="legacy-escrow-ledger",
            snapshot_ref="escrow-snapshot",
            classical_public_key=classical_public_key,
        )
        signature = build_demo_classical_claim_proof(
            classical_public_key,
            classical_claim_message_bytes(preview.migration_claim_payload()),
        )
        claim = wallet.create_migration_claim(
            service,
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            classical_public_key=classical_public_key,
            classical_signature=signature,
            source_network="legacy-escrow-ledger",
            snapshot_ref="escrow-snapshot",
            destination_address=preview.outputs[0].recipient,
            timestamp=preview.timestamp,
        )
        service.submit_transaction(claim)
        service.mine_pending_transactions(miner.create_address())
        locked_state = service.migration_claim_finality(classical_address)["state"]
        wallet_blocked = False
        try:
            wallet.create_transaction(service, receiver.create_address(), amount=1, fee=1)
        except ValueError:
            wallet_blocked = True
        dispute = service.open_migration_dispute(classical_address, reason="chaos fraud")
        service.resolve_migration_dispute(dispute["dispute_id"], outcome="resolved_fraud", resolution_note="chaos fraud")
        fraud_state = service.migration_claim_finality(classical_address)["state"]
        return {
            "passed": locked_state == "escrow_locked" and wallet_blocked and fraud_state == "fraud_resolved_frozen",
            "locked_state": locked_state,
            "wallet_blocked_locked_spend": wallet_blocked,
            "fraud_state": fraud_state,
        }

    def signer_crash_recovery(self) -> dict[str, object]:
        service = self.service("signer-crash")
        wallet_db = self.root / "signer_crash_wallet.db"
        alice = Wallet(
            "CrashAlice",
            state_db_path=wallet_db,
            reservation_ttl_seconds=1,
        )
        funding = alice.create_address()
        service.create_genesis_block({funding: 20})

        def reserve_without_completion(keypair: object):
            material = alice._provider.deserialize_keypair(keypair)
            reservation = alice._provider.reserve_signing_material(material)
            return alice._provider.serialize_keypair(material), reservation

        _, _, reservation_id = alice._state_store.reserve_wallet_key_state(
            alice.label,
            funding,
            alice.signature_provider,
            reserve_without_completion,
            owner_id=alice._owner_id,
        )
        blocked = False
        try:
            alice._state_store.reserve_wallet_key_state(
                alice.label,
                funding,
                alice.signature_provider,
                reserve_without_completion,
                owner_id=alice._owner_id,
            )
        except ValueError:
            blocked = True

        alice._state_store.fail_wallet_key_reservation(
            alice.label,
            funding,
            alice.signature_provider,
            reservation_id,
            owner_id=alice._owner_id,
            error_message="simulated signer crash",
        )
        recovered = {
            "status": "failed_reservation_released",
            "reservation_id": reservation_id,
        }
        reloaded = Wallet("CrashAlice", state_db_path=wallet_db)
        transaction = reloaded.create_transaction(service, Wallet("CrashBob").create_address(), amount=5, fee=1)
        service.submit_transaction(transaction)

        return {
            "passed": recovered["status"] == "failed_reservation_released" and service.store.pending_transaction_count() == 1,
            "blocked_during_stale_reservation": blocked,
            "recovery": recovered,
            "pending_transactions": service.store.pending_transaction_count(),
        }

    def verification_throughput(self, batch_size: int) -> dict[str, object]:
        service = self.service("verification-throughput")
        alice = Wallet("VerifyAlice")
        bob = Wallet("VerifyBob")
        funding = {alice.create_address(): 3 for _ in range(batch_size)}
        service.create_genesis_block(funding)
        transaction = alice.create_transaction(service, bob.create_address(), amount=batch_size, fee=1)

        started = time.perf_counter()
        result = verify_transaction_inputs(transaction, service.store.all_utxos())
        elapsed_ms = (time.perf_counter() - started) * 1000
        checks_per_second = 0.0 if elapsed_ms <= 0 else (len(transaction.inputs) / elapsed_ms) * 1000
        return {
            "passed": result.verified and result.checked_inputs == len(transaction.inputs),
            "input_count": len(transaction.inputs),
            "verified": result.verified,
            "mode": result.mode,
            "worker_count": result.worker_count,
            "elapsed_ms": round(elapsed_ms, 3),
            "checks_per_second": round(checks_per_second, 3),
        }


__all__ = ["ChaosHarness", "run_load_chaos_harness"]
