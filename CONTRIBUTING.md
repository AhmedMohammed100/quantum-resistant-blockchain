# Contributing to QBC

Thank you for helping improve QBC.

## Before you contribute

QBC is a protocol and blockchain implementation. Changes affecting
consensus, transaction validation, serialization, cryptography, migration,
state roots, networking, or signer state require particular care.

For significant protocol or consensus changes, open an issue or discussion
before submitting a pull request so the design can be reviewed first.

## Pull requests

Please:

- keep consensus-critical behavior aligned with `protocol.md`;
- add or update regression tests for security and consensus changes;
- document changes to protocol behavior;
- avoid silently changing canonical serialization;
- do not introduce cryptographic fallbacks or algorithm downgrades;
- keep secrets, private keys, credentials, and local state out of commits;
- run the test suite before submitting a pull request.

## Contributions and license

By intentionally submitting a contribution for inclusion in QBC, you agree
that the contribution is provided under the Apache License, Version 2.0,
consistent with the repository's licensing terms, unless a separate written
agreement applies.

You retain copyright in your contribution.

## Security issues

Please do not disclose security vulnerabilities in public issues.
Follow SECURITY.md for responsible disclosure.
