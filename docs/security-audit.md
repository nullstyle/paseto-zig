# Security audit checklist — untrusted-input surface

Self-audit of every entry point that consumes attacker-controlled bytes,
performed for the 0.3.0 release. This is a first-party review against the
PASETO and PASERK specifications and standard cryptographic review practice;
it is **not** a third-party audit (see `SECURITY.md`).

Each item records the applicable spec area, the disposition
(`verified` / `fixed` / `documented`), and where the behavior is pinned by a
test. Input size caps referenced throughout live in `src/util.zig`:
`max_token_string_bytes` (1 MiB), `max_claims_json_bytes` (64 KiB),
`max_pem_bytes` (64 KiB), `max_paserk_string_bytes` (4096).

## 1. Token framing — `src/token.zig`

| Check | Disposition | Evidence |
| --- | --- | --- |
| Total input capped before any parsing or allocation | verified | `parse` rejects > 1 MiB with `InvalidToken` first; boundary pinned by e2e "token parser enforces the 1 MiB cap at the boundary" (exactly-at-cap parses, cap+1 rejects) |
| Header parsed by full-string equality; no prefix confusion (`v4x` ≠ `v4`) | verified | `Version.fromString` / `Purpose.fromString` compare complete segments |
| Exactly 3 or 4 dot-separated segments; 5th segment rejected | verified | `tests/fuzz/token.zig` seeds (`too_many_dots`), fuzz error contract |
| Base64url is unpadded and canonical (trailing bits zero, `=` rejected) | verified | `util.decodeBase64Alloc`; padded input rejected in e2e "Token parser rejects malformed inputs" |
| Decoded payload never larger than its encoded segment (allocation bounded by input) | verified | decoder sizing comes from `calcSizeForSlice`; no decode-then-truncate |
| No partial-secret leak on malformed input | verified | `errdefer secureFree` on payload/footer paths; `Token.deinit` zeroizes |
| Implicit assertion is an API argument, never token content | verified | matches PASETO spec: IA is bound into the PAE but not carried in the token |

## 2. PAE (pre-auth encoding) — `src/util.zig`

| Check | Disposition | Evidence |
| --- | --- | --- |
| `LE64(n) ‖ (LE64(len) ‖ part)*` per spec | verified | unit test "PAE matches spec examples" (empty, `[""]`, `["test"]`) |
| Length arithmetic overflow-checked | verified | `std.math.add` sizing loop |
| Spec's high-bit length mask enforced in release builds | fixed | was a `std.debug.assert` (release no-op); now a checked `Error.Overflow` in the sizing loop before allocation |
| Total size bounded by the caller-side input caps | verified | every PAE in this library is built from ≤ 1 MiB token-derived parts |

## 3. v4.local (XChaCha20 + keyed BLAKE2b) — `src/v4/local.zig`

| Check | Disposition | Evidence |
| --- | --- | --- |
| Version+purpose checked before any crypto | verified | `WrongPurpose` on non-`v4.local` tokens |
| Pre-decrypt length floor (nonce 32 + tag 32) | verified | `MessageTooShort` |
| PAE covers header, nonce, ciphertext, footer, implicit assertion | verified | footer tamper + wrong-IA e2e negatives; official v4 vectors |
| MAC verified **before** decryption | verified | tag compare precedes `xor` |
| Tag comparison constant-time | verified | `util.constantTimeEqual` (branch-free accumulate; unit-tested, incl. length mismatch) |
| Keyed BLAKE2b parameter-block installation correct | fixed | bespoke in-place `setBlake2bKey` unified into `util.setBlake2bKey` and pinned to `std.crypto`'s keyed init — which is itself validated against the official BLAKE2 KATs — by unit test "setBlake2bKey matches std keyed init across sizes" (3 digest sizes × 5 key lengths × 6 message lengths); official v4 vectors pass through the same path |
| Key-material hygiene on the stack | fixed | in-place keyed init + `defer secureZero` on every hash state and derived-key struct; the by-value keyed inits in PIE/PKE/PBKW were converted to the same pattern (previously they left padded key blocks in return frames) |
| Subkey derivation (`paseto-encryption-key` / `paseto-auth-key-for-aead`) | verified | official v4.local vectors (HKDF-like BLAKE2b derivations) |

## 4. v4.public (Ed25519) — `src/v4/public.zig`

| Check | Disposition | Evidence |
| --- | --- | --- |
| Version+purpose + length floor (sig 64) before crypto | verified | `WrongPurpose` / `MessageTooShort` |
| PAE covers header, message, footer, implicit assertion | verified | signature-tamper and wrong-IA e2e negatives; official vectors |
| Signature verification constant-time | verified | std `Ed25519.Signature.verify` |
| Wrong-key verification rejected | verified | e2e "v4.public rejects verification with wrong key" |

## 5. v3.local (AES-256-CTR + HMAC-SHA384) — `src/v3/local.zig`

| Check | Disposition | Evidence |
| --- | --- | --- |
| Version+purpose + length floor (nonce 32 + tag 48) | verified | `WrongPurpose` / `MessageTooShort` |
| HKDF-SHA384 subkeys; PAE binds footer + implicit assertion | verified | official v3.local vectors; **v3 footer-tamper and wrong-IA e2e negatives added** (previously only v4 was covered) |
| MAC before decrypt; constant-time tag compare | verified | same structure as v4.local |

## 6. v3.public (ECDSA P-384) — `src/v3/public.zig`

| Check | Disposition | Evidence |
| --- | --- | --- |
| PAE includes the public key first (v3-specific ordering) | verified | official v3.public vectors |
| Signature tamper + wrong IA rejected | fixed (test gap) | e2e negatives added for both |
| std ECDSA verification | verified | `crypto.sign.ecdsa.EcdsaP384Sha384` |

## 7. PASERK surface — `src/paserk/*`

| Check | Disposition | Evidence |
| --- | --- | --- |
| 4096-byte cap on all PASERK strings | verified | boundary test: exactly-at-cap proceeds to key validation (`InvalidKey`), cap+1 returns `InvalidEncoding` |
| Exact expected base64 length checked **before** decode/alloc | verified | `keys.parse`, `pie.unwrap`, `pke.unseal*`, `pbkw.unwrapWithPolicy` all compare `encodedBase64Len` first |
| Key material validated after decode (curve, point, seed consistency) | verified | `validateKeyMaterial`; official PASERK vectors |
| `fromPaserk` re-checks version and kind (`k3.local` → `v4.Local` rejects) | verified | `WrongVersion`/`WrongPurpose`; fuzz scenario `mixed_version_misuse` |
| PIE: header string MAC-bound; MAC before decrypt | verified | cross-kind and cross-version header-confusion e2e negatives added (`k4.local-wrap.pie` body under `k4.secret-wrap.pie` / `k3.` prefixes rejects) |
| PKE: ephemeral keys validated (low-order X25519 rejected, on-curve P-384); tag before decrypt | verified | `X25519.scalarmult` rejection, `P384.fromSec1`; cross-version `k4.seal`→`k3.seal` e2e negative added |
| PBKW: wire-controlled KDF params validated against policy **before** the KDF runs | verified | `WeakParameters` negatives in `src/paserk/pbkw.zig` unit tests (non-KiB memlimit, over-limit params) |
| PBKW: wrong password and tampered tag rejected | fixed (test gap) | e2e "PBKW unwrap rejects wrong password and tampered tag" added |
| PASERK IDs: fixed-size stack decode, no allocation; digest equality constant-time | verified | `Id.parse` length-first decode; `Id.eql` |

## 8. PEM / DER — `src/pem.zig`

| Check | Disposition | Evidence |
| --- | --- | --- |
| 64 KiB cap before framing | verified | e2e over-cap negative |
| Strict single-block framing; nested BEGIN killed by body charset | verified | existing unit tests (leading/trailing garbage, concatenated blocks) |
| DER: long-form lengths bounded (n ∈ 1..4), indefinite forbidden, truncation and overrun rejected | verified | unit test "DER walker rejects malformed long-form lengths" added (indefinite `0x80`, n=5, truncated, overrun, near-u32-max); the `Overflow` branch additionally guards 32-bit targets |
| DER containers exhaustive (no trailing garbage); OID whitelists; RFC 8410 NULL-parameters rejection | verified | existing unit tests |

## 9. Claims parsing & validation — `src/claims.zig`

| Check | Disposition | Evidence |
| --- | --- | --- |
| 64 KiB cap enforced on **every** entry point | fixed | was Validator-only, leaving `Claims.init`/`Claims.parsed` unbounded; `Claims.init` now rejects > 64 KiB with `InvalidClaim` (boundary-tested) |
| JSON nesting bounded by the input cap | verified | `std.json.parseFromSlice` over capped input |
| Timestamp parsing width-checked, no overflow | verified | bounded decimal parser, offset range checks, Hinnant `daysFromCivil` |
| `expected_*` string comparisons (`iss`, `aud`, `sub`, `jti`) | fixed | all four now use `util.constantTimeEqual`; the `aud` scan evaluates every candidate with no early break (unit test "validator audience list scans every candidate") |

## 10. WASM ABI — `src/wasm.zig`

The host is untrusted from the module's perspective (it supplies every
pointer, length, and nonce).

| Check | Disposition | Evidence |
| --- | --- | --- |
| Frame parsers enforce `max_abi_input_bytes` and exact consumption (trailing bytes reject) | verified | `tests/wasm_abi.zig` |
| All pointers range-checked against the fixed arena with overflow-checked ends; low-memory pointers rejected | verified | `heapSlice`/`rangeInHeap`; ABI tests |
| Fixed 8 MiB arena bounds worst-case allocation; exhaustion returns `out_of_memory` | verified | `free` wipes without reclaiming — bounded exhaustion, reset requires `resetAllocator` |
| Full arena wipe between operations | verified | ABI tests |

## 11. Resource-exhaustion posture

- **PBKW unwrap** necessarily runs Argon2id/PBKDF2 *before* tag verification
  (the KDF output keys the MAC). Wire parameters are validated against the
  production policy (v4: 64–256 MiB, opslimit 2–3, `para == 1`; v3:
  1,000–10,000 iterations) before the KDF runs, so a malicious PASERK can
  force at most one policy-maximum KDF per attempt — the same order as an
  honest password guess. Documented in `SECURITY.md`.
- **Token/claims/PEM/PASERK parsers** allocate only after size caps, and
  decoded sizes never exceed encoded sizes; no quadratic parsing on
  attacker-controlled repetition.
- **v3.public verification** uses P-384 scalar multiplication on
  attacker-chosen points after on-curve validation (standard cost).

## 12. Residual risks

- No third-party cryptographic audit has been performed (a threat model
  now exists in `docs/threat-model.md` as groundwork for one).
- `Claims` struct literals can be built by field access, bypassing
  `Claims.init`'s cap; `Claims.parsed` now enforces the same cap before
  parsing, so every remaining JSON entry point on the type is bounded
  (unit test "Claims.parsed enforces the cap for struct literals").
- The freestanding WASM module trusts the host for nonce entropy by design;
  a host that repeats nonces with the same key breaks confidentiality
  (documented in `docs/wasm.md`).

## 13. Verification index

Every row above maps to at least one of: official vector files under
`tests/vectors/` (17 files: v3, v4, and 15 PASERK operations), the e2e
negatives in `tests/e2e.zig`, the fuzz error contracts in `tests/fuzz/`
(14 harnesses with corpus and regression inputs, including
`mixed_version_misuse` and `mixed_purpose_misuse` scenario families), the
WASM ABI tests in `tests/wasm_abi.zig`, or the unit tests embedded in the
source files.
