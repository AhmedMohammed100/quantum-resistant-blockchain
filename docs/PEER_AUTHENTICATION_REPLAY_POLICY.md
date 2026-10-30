# Peer Request Nonce Replay Retention

Each signed peer request must carry a non-empty UTF-8 nonce no longer than 128 bytes. Nonce uniqueness is enforced per peer identity.

A node retains nonce records for 2 * auth_time_skew_seconds + 1 seconds after receipt. This covers the full validity interval of an accepted signed timestamp, including timestamps that were at the future edge of the allowed skew. On each accepted peer request, expired records are deleted before the new nonce is inserted. A timestamp-expired envelope is rejected before nonce processing.

This is a peer API resource and replay-protection policy. It does not change block serialization, transaction IDs, consensus, or the v2 protocol profile.
