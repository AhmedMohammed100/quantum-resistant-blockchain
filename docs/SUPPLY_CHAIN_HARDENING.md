# Supply-chain hardening

## Immutable CI actions

Every action used by the repository workflows is pinned to a full commit SHA.
The inline version comment records the upstream major tag used when selecting
the commit. Dependabot is configured to propose weekly action updates; review
the upstream release and resolved commit before accepting an update.

## Dependency vulnerability checks

The scheduled and pull-request dependency audit covers:

- The optional Python OQS binding declared in `requirements-oqs.txt`, including
  its resolved Python dependency metadata, with a pinned `pip-audit` release.
- The native Rust signer dependency graph from its committed `Cargo.lock`,
  using a pinned `cargo-audit` release and the RustSec advisory database.

Dependabot also checks the Python, Cargo, and GitHub Actions ecosystems weekly
and can open update pull requests. The audit is a known-advisory check, not a
cryptographic review or a guarantee that upstream dependencies are safe. The
native `liboqs` runtime built or installed outside the Python package graph
must be tracked and assessed separately by deployment maintainers.
