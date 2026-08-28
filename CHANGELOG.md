# Changelog

## 0.3.0

- Added a mise-pinned Binaryen 130 post-processing step, reducing the
  ReleaseSafe WASM artifact from 46,997 to 39,948 bytes while preserving the
  exact ABI, low-pointer rejection, and memory-wiping checks.
- Replaced broad dynamic exporting with an explicit ABI symbol allowlist and
  exported memory.
- Added a ReleaseSafe freestanding WASM build for PASETO v4.local seal/open
  and PASERK local-key IDs.
- Added a versioned packed ABI with host-supplied nonces, authenticated footer
  framing, bounded allocation, and full arena wiping between operations.
- Added focused ABI tests and documented browser/Deno loading semantics.

## 0.2.0

- Hardened claims validation so `expected_*` fields require claim presence.
- Added production PBKW resource policies and explicit low-cost testing policy.
- Added parser size caps and stricter PASERK/PEM key validation.
- Added footer-preserving decode/verify helpers and PASERK-to-key constructors.
- Added Zig development snapshot compatibility while retaining Zig `0.16.0`.
- Added first-party security policy, vector provenance, and downstream consumer
  smoke testing.

## 0.1.0

- Initial Zig package release with PASETO v3/v4 local/public support.
- Added PASERK key serialization, IDs, PIE, PKE, and PBKW operations.
- Added official vector tests, end-to-end smoke tests, and deterministic fuzz
  seed harnesses.
