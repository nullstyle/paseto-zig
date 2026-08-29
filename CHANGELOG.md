# Changelog

## 0.4.0

- Closed the audit residuals: `Claims.parsed` now enforces the 64 KiB cap
  (closing the struct-literal bypass) and maps JSON parse failures onto the
  library error set; expected `iss`/`aud`/`sub`/`jti` claims compare in
  constant time with a full audience scan.
- Hardened key-material lifetime from an independent three-lens review:
  v3 key derivation and AES-CTR now take pointers instead of copying the
  master key into extra stack frames, the v3 scalar import wipes its local
  copy, every HMAC/SHA384 state absorbing key material is defer-wiped, PKE
  unseal wipes its seed/secret copies, and the WASM export path guards
  u32 descriptor writes with the same arena-fit check as `allocate`.
- Added `wipe()` to v3/v4 `Local` and `Public` so callers can zero key
  values without hand-rolling secureZero calls.
- Documented the review's confirmations and the deliberate policy choices
  (PBKW receiver-side parameter bounds, PIE v3 spec-prose vs vector
  conflict) in `docs/security-audit.md`; added `docs/threat-model.md`.
- Added a nightly mutation-fuzz workflow over the parser, envelope, and
  scenario groups on the pinned dev snapshot, with crash-evidence upload.
- Extended the ruby-paseto interop fixtures beyond tokens to the PASERK
  key-management operations: fresh PIE local-wrap/secret-wrap, PKE seal,
  and PBKW password-wrap outputs from the vendored reference are unwrapped
  by `zig build interop` with recovered key material required to match
  byte-for-byte (PIE v4 under deterministic nonces; PBKW under the default
  production policy, plus a wrong-password negative).

## 0.3.0

### Freestanding WebAssembly module

- Added a ReleaseSafe freestanding WASM build for PASETO v4.local seal/open
  and PASERK local-key IDs: a versioned packed ABI with host-supplied
  nonces, authenticated footer framing, bounded allocation, and full arena
  wiping between operations.
- Added a mise-pinned Binaryen 130 post-processing step, reducing the
  artifact from 46,997 to 39,948 bytes while preserving the exact ABI,
  low-pointer rejection, and memory-wiping checks.
- Replaced broad dynamic exporting with an explicit ABI symbol allowlist and
  exported memory; stripped symbols keep clean-cache builds byte-for-byte
  reproducible for hash-pinned consumers.
- Added focused ABI tests (`zig build wasm-test`), the exact ABI/frame/status
  documentation in `docs/wasm.md`, and a Deno engine smoke test
  (`tests/wasm/deno_smoke.ts`) that proves the documented loading semantics
  against the shipped artifact in CI, including negative paths.

### Audit-driven hardening

- Performed a first-party untrusted-input audit across token framing, PAE,
  all four cipher purposes, every PASERK operation, PEM/DER, claims
  validation, and the WASM ABI; the checklist, dispositions, and pinning
  tests are recorded in `docs/security-audit.md`.
- Unified all keyed-BLAKE2b use on an in-place parameter-block installation
  (`util.setBlake2bKey`) so key material exists in exactly one wipeable
  state per operation, and pinned it to `std.crypto`'s keyed init (RFC
  KAT-validated) across 90 size combinations plus the official vectors.
- Enforced the 64 KiB claims cap in `Claims.init` (previously only the
  validator capped it) and replaced the release-inert PAE length assert
  with a checked overflow error raised before allocation.
- Closed test gaps: v3 footer/implicit-assertion tamper negatives, parser
  cap boundary tests (1 MiB token, 4096-byte PASERK, 64 KiB claims/PEM),
  PBKW wrong-password and tampered-tag negatives, PIE/PKE cross-kind and
  cross-version header-confusion negatives, and DER long-form length edge
  cases.
- Documented the PBKW work-factor posture and claims comparison timing in
  `SECURITY.md`.

### Cross-implementation interop

- Added fixture-based interop testing against the vendored ruby-paseto
  reference: `tools/interop/generate.rb` produces byte-stable v4 fixtures
  (and valid v3 fixtures) that `zig build interop` consumes — decrypting
  and verifying fresh foreign tokens, matching PASERK strings, requiring
  identical lid/pid/sid derivations, and feeding every foreign token into
  each wrong version/purpose entry point as a confusion negative.
  Provenance and regeneration steps live in
  `tests/vectors-interop/PROVENANCE.md`; CI needs no Ruby.

### Toolchain and release hygiene

- Made `build.zig` compile on both Zig 0.16.0 and current 0.17 dev
  snapshots (comptime resolve for the optimize-enum rename) and added a
  non-gating CI canary running unit/e2e/WASM-ABI tests on a pinned dev
  snapshot, since downstream consumers build the tarball with dev
  toolchains.
- Documented that the pinned stable toolchain owns `zig fmt`.
- Added `tools/release-check.sh` (wired into CI and `mise run ci`):
  the README fetch tag and `build.zig.zon` version must agree, and tag
  builds must match the zon version exactly.
- Expanded the CI matrix to Linux arm64, Linux x86_64, and macOS, with
  WASM build, vector, interop, fuzz, and consumer smoke steps.

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
