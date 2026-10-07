# Security Policy

QBC is experimental blockchain and post-quantum cryptography software.
It is not currently suitable for production custody or real user funds.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a suspected security
vulnerability.

Use GitHub's private vulnerability reporting/security advisory mechanism for
this repository when available, or contact the repository owner privately
through GitHub with:

- a clear description of the vulnerability;
- affected commit, branch, or version;
- reproducible steps or a proof of concept;
- security impact;
- suggested mitigation, if known.

Please avoid including private keys, credentials, or other sensitive data
in reports.

## What should be reported privately

Examples include:

- consensus or supply inflation;
- signature verification bypasses;
- stateful signer/one-time-key reuse;
- migration claim bypasses;
- peer authentication or replay vulnerabilities;
- unauthorized privileged API operations;
- state corruption or recovery bypasses.

## Disclosure

We will determine an appropriate disclosure timeline based on severity,
exploitability, affected deployments, and availability of a fix.
