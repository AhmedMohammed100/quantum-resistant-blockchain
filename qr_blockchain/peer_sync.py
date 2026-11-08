"""Authenticated peer chain synchronization policy.

The node-facing methods are supplied through a small protocol so sync policy
can be reasoned about separately from API routing and block persistence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from .models import Block
from .network import normalize_peer_url, with_path

if TYPE_CHECKING:
    from .storage import SQLiteChainStore


class PeerSyncHost(Protocol):
    store: SQLiteChainStore

    def ensure_peer_admission(self, peer_url: str) -> dict[str, object]: ...

    def _fetch_peer_json(self, url: str, **kwargs) -> dict[str, object]: ...

    def _build_peer_request_frame(
        self,
        *,
        message_type: str,
        payload: dict[str, object],
        auth: dict[str, object],
    ) -> dict[str, object]: ...

    def build_peer_session_envelope(
        self,
        purpose: str,
        peer_url: str,
        session_id: str,
        request_path: str,
        request_claims: dict[str, object] | None = None,
    ) -> dict[str, object]: ...

    def _parse_peer_response_frame(self, frame: dict[str, object], expected_message_type: str) -> dict[str, object]: ...

    def import_block(self, block: Block) -> None: ...


def sync_with_peer(node: PeerSyncHost, peer_url: str) -> int:
    normalized = normalize_peer_url(peer_url)
    session = node.ensure_peer_admission(normalized)
    try:
        summary = node._fetch_peer_json(
            with_path(normalized, "/peer/summary"),
            method="POST",
            payload=node._build_peer_request_frame(
                message_type="peer_summary_request",
                payload={},
                auth=node.build_peer_session_envelope(
                    "peer_summary_v2",
                    normalized,
                    str(session["session_id"]),
                    "/peer/summary",
                ),
            ),
        )
        summary_payload = node._parse_peer_response_frame(summary, "peer_summary_response")
        remote_count = int(summary_payload.get("height", 0))
        if remote_count < 0:
            raise ValueError("Peer advertised an invalid chain height.")
        remote_head_hash = str(summary_payload.get("best_head_hash", ""))
        local_count = node.store.block_count()
        local_head_hash = node.store.best_head_hash() or ""
        imported = 0
        should_sync = remote_count > local_count or (
            remote_count == local_count and remote_head_hash > local_head_hash
        )
        if should_sync:
            # The summary height is a block count. Start at the local tip so
            # equal-height forks can be compared; if that block does not share
            # a known parent, exponentially walk back to a common ancestor.
            start_height = max(0, min(local_count, remote_count) - 1)
            backtrack = 1
            blocks = _fetch_blocks(node, normalized, str(session["session_id"]), start_height)
            while True:
                if not blocks:
                    raise ValueError("Peer advertised a longer chain but returned no blocks.")
                if blocks[0].index != start_height:
                    raise ValueError("Peer block response does not begin at the requested height.")
                if blocks[0].index == 0 or node.store.has_block(blocks[0].previous_hash):
                    break
                if start_height == 0:
                    raise ValueError("Peer chain does not connect to a known genesis block.")
                start_height = max(0, start_height - backtrack)
                backtrack *= 2
                blocks = _fetch_blocks(node, normalized, str(session["session_id"]), start_height)

            next_start_height = start_height
            while next_start_height < remote_count:
                if not blocks:
                    raise ValueError("Peer stopped returning blocks before its advertised height.")
                if blocks[0].index != next_start_height or any(
                    right.index != left.index + 1 for left, right in zip(blocks, blocks[1:])
                ):
                    raise ValueError("Peer block response heights are not contiguous.")
                for block in blocks:
                    if not node.store.has_block(block.block_hash):
                        node.import_block(block)
                        imported += 1
                next_start_height = blocks[-1].index + 1
                if next_start_height >= remote_count:
                    break
                if next_start_height <= start_height:
                    raise ValueError("Peer block response did not advance the requested height.")
                start_height = next_start_height
                blocks = _fetch_blocks(node, normalized, str(session["session_id"]), start_height)

        node.store.add_peer(normalized)
        node.store.record_peer_sync_result(
            str(session["node_id"]),
            success=True,
            score_delta=max(1, imported),
        )
        return imported
    except Exception:
        node.store.record_peer_sync_result(str(session["node_id"]), success=False, score_delta=-5)
        raise


def _fetch_blocks(node: PeerSyncHost, peer_url: str, session_id: str, start_height: int) -> list[Block]:
    request_payload = {"start_height": start_height}
    response = node._fetch_peer_json(
        with_path(peer_url, "/peer/blocks"),
        method="POST",
        payload=node._build_peer_request_frame(
            message_type="peer_blocks_request",
            payload=request_payload,
            auth=node.build_peer_session_envelope(
                "peer_blocks_v2",
                peer_url,
                session_id,
                "/peer/blocks",
                request_payload,
            ),
        ),
    )
    response_payload = node._parse_peer_response_frame(response, "peer_blocks_response")
    return [Block.from_dict(item) for item in response_payload.get("blocks", [])]

