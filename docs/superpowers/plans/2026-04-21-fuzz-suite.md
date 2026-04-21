# Paseto Zig Built-In Fuzzing Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land a complete, locally-invoked fuzz-testing suite for `paseto-zig` using only Zig's built-in fuzzing facilities (`std.testing.fuzz`, `std.testing.Smith`, `-ffuzz`, `zig build <step> --fuzz[=limit]`, `--webui`). The suite must have enough breadth and throughput to saturate a Mac Studio for long sessions (≈48 hours) while keeping failures attributable to narrow harnesses.

**Architecture:** Implement 13 harnesses following the approved design in `docs/superpowers/specs/2026-04-21-fuzz-suite-design.md` as a dedicated `tests/fuzz/` subsystem. Do not change production source files except to add tightly-scoped fuzz-only helpers where internal boundaries are better crash surfaces than public APIs. Build out the suite in six ordered workstreams: scaffolding, parser harnesses, envelope harnesses, high-level API harnesses, scenario harness, and corpus/regression/DX polish.

**Tech Stack:** Zig `0.16.0`, `std.testing.fuzz`, `std.testing.Smith`, `std.Build` module with `.fuzz = null` (toolchain follows `--fuzz`), `@embedFile` for seed corpora, PASETO/PASERK test vectors already present in `tests/vectors/*.json`.

**Known platform blocker on stock Zig 0.16.0 (2026-04-21):** `-ffuzz` currently fails to compile the stdlib test runner because `@errorReturnTrace()` returns `*builtin.StackTrace` but `std.debug.writeStackTrace` in 0.16.0 expects `*const debug.StackTrace` (same name, different types). This is a 0.16.0-only defect at `/lib/compiler/test_runner.zig:566`. Decision (2026-04-21): land the **entire** plan in seed-only mode — every harness uses `std.testing.fuzz(..., .{ .corpus = &seeds })` and runs its embedded corpus once per invocation. Generative fuzzing turns on automatically the day either (a) Zig patches the test runner, or (b) a user opts into a forked test_runner. Do not add `--fuzz` invocations to task verification steps; replace them with plain seed-only `zig build fuzz-*` runs.

---

## Context Snapshot

- `zig build test` is green on `main` (unit + vectors + e2e) after the 2026-04-21 remediation plan.
- Zig `0.16.0` exposes `std.testing.fuzz`, `std.testing.Smith`, `-ffuzz`, `zig build <step> --fuzz[=KMG]`, and `--webui` in the stock toolchain.
- No fuzz harnesses exist in the repo yet; `tests/fuzz/` does not exist.
- Official PASETO/PASERK vectors live at `tests/vectors/*.json` (both positive and `expect-fail` cases). They are the best ready-made seed material.
- Public surface sheet collected during planning (keep handy while writing harnesses):
  - Parser-shaped: `token.parse`, `util.decodeBase64Alloc`, `util.hexDecodeAlloc`, `util.preAuthEncodeAlloc`, `claims.Validator.validate`, `claims.parseIsoTimestamp`, `pem.pemToDer`, `pem.parse`, `paserk.keys.parse`.
  - Envelope-shaped: `paserk.pie.unwrap`, `paserk.pke.unsealV3`/`unsealV4`/`unsealV4FromSecretKey`, `paserk.pbkw.wrapV3`/`wrapV4`/`unwrap`, `paserk.id.lid`/`sid`/`pid`/`compute`.
  - High-level: `v3.Local`/`v4.Local` `decrypt`, `v3.Public`/`v4.Public` `verify` and their constructors.
- No other concurrent workstreams are in flight.

## Guardrails For The Implementing Agent

- Do NOT modify cryptographic code. Harnesses consume the existing APIs.
- Do NOT broaden or alter the public `Error` set. If a harness hits an error that is not in the declared contract, STOP and surface the drift — do not casually widen the allowed set.
- Keep fuzz-only helpers small, clearly labeled (`// fuzz/test-only`), and confined to `tests/fuzz/`.
- Do not add `.fuzz = true` on modules; leave it `null` so toolchain opt-in drives `-ffuzz`. Otherwise `zig build test` (without `--fuzz`) panics with "fuzz test requires server".
- Every harness must remain runnable without `--fuzz` — seed-only execution exercises corpus entries once each and must pass.
- Keep inputs bounded: default ≤ 4096 bytes per generated string unless a harness specifically targets size scaling.
- PBKW harness cost parameters must stay in fuzz-mode territory (`memlimit_bytes = 8192` / `opslimit = 1` for v4, small iteration count for v3).
- Corpora live under `tests/fuzz/corpus/<harness>/`; regressions under `tests/fuzz/regressions/<harness>/`. Do not share corpora across harnesses.
- Commit after each completed task, not per-harness sub-step.
- If a fuzz run in CI-like conditions (short wall-clock) produces a reproducible crash, promote it to a regression seed or an explicit unit test before ending the task; do not silence it.
- Respect rejection-contract limits from the spec verbatim — the allowed-error lists are not suggestions.

## File Map

- Create: `tests/fuzz/support.zig`
  Purpose: Shared Smith helpers, bounded-size constants, token-mutation helper, allowed-error wrappers, corpus embed helpers.
- Create: `tests/fuzz/token.zig`
  Purpose: Parser harness for `src/token.zig`.
- Create: `tests/fuzz/util.zig`
  Purpose: Parser harness for `src/util.zig` (base64url, hex, PAE).
- Create: `tests/fuzz/claims.zig`
  Purpose: Parser harness for `src/claims.zig` validator and timestamp parser.
- Create: `tests/fuzz/pem.zig`
  Purpose: Parser harness for `src/pem.zig` framing and DER walker.
- Create: `tests/fuzz/paserk_keys.zig`
  Purpose: Parser harness for `src/paserk/keys.zig`.
- Create: `tests/fuzz/paserk_pie.zig`
  Purpose: Envelope harness for `src/paserk/pie.zig`.
- Create: `tests/fuzz/paserk_pke.zig`
  Purpose: Envelope harness for `src/paserk/pke.zig`.
- Create: `tests/fuzz/paserk_pbkw.zig`
  Purpose: Envelope harness for `src/paserk/pbkw.zig`.
- Create: `tests/fuzz/paserk_id.zig`
  Purpose: High-level harness for `src/paserk/id.zig`.
- Create: `tests/fuzz/v4_local.zig`
  Purpose: High-level harness for `src/v4/local.zig`.
- Create: `tests/fuzz/v4_public.zig`
  Purpose: High-level harness for `src/v4/public.zig`.
- Create: `tests/fuzz/v3_local.zig`
  Purpose: High-level harness for `src/v3/local.zig`.
- Create: `tests/fuzz/v3_public.zig`
  Purpose: High-level harness for `src/v3/public.zig`.
- Create: `tests/fuzz/scenarios.zig`
  Purpose: Scenario harness covering all 10 scenario families from the spec.
- Create: `tests/fuzz/corpus/<harness>/...seed files`
  Purpose: Initial seed corpora per harness, drawn from official vectors and hand-curated edge cases.
- Create: `tests/fuzz/regressions/<harness>/` directories (empty at land time)
  Purpose: Placeholder for future crash-minimization seeds.
- Modify: `build.zig`
  Purpose: Add `fuzz-parsers`, `fuzz-envelopes`, `fuzz-scenarios`, `fuzz-all` steps plus per-harness steps; each step rebuilds a separate test binary so one harness crash does not block others.
- Modify: `README.md`
  Purpose: Document the fuzz workflow under a new "Fuzzing" section: `zig build fuzz-all --fuzz`, `--webui`, per-harness targeting, regression policy.
- Optional modify: none expected in `src/` during this plan. If a fuzz-only helper must live in a source module (e.g. a public test entrypoint), gate it with `@import("builtin").is_test` and annotate it as fuzz/test-only.

## Recommended Execution Order

1. Fuzz scaffolding (build graph, shared support, dirs, smoke test)
2. Parser harnesses (token, util, claims, pem, paserk/keys)
3. Envelope harnesses (paserk/pie, paserk/pke, paserk/pbkw, paserk/id)
4. High-level API harnesses (v4.local, v4.public, v3.local, v3.public)
5. Scenario harness
6. Corpus, regressions, and developer UX polish

Each task verifies via `zig build fuzz-all` (no `--fuzz`, seed-only) before committing. Long-run fuzz sessions are opt-in and not required to land the task.

---

### Task 1: Fuzz Scaffolding

**Files:**
- Create: `tests/fuzz/support.zig`
- Create: `tests/fuzz/corpus/.gitkeep`
- Create: `tests/fuzz/regressions/.gitkeep`
- Modify: `build.zig`

- [ ] **Step 1: Confirm seed-only fuzz compiles**

Write a throwaway harness at `tests/fuzz/_smoke.zig`:

```zig
const std = @import("std");
test "fuzz toolchain smoke" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, s: *std.testing.Smith) anyerror!void {
            var buf: [16]u8 = undefined;
            _ = s.slice(&buf);
        }
    }.run, .{});
}
```

Run: `zig test tests/fuzz/_smoke.zig`

Expected: passes (seed-only; empty corpus means zero iterations). Delete `_smoke.zig` after this check.

Do NOT attempt `-ffuzz` on stock Zig 0.16.0 — it fails at comptime due to the known stdlib test_runner defect documented above. The seed-only mode is the targeted build mode for this plan.

- [ ] **Step 2: Create `tests/fuzz/support.zig`**

Contents outline:

```zig
const std = @import("std");
const paseto = @import("paseto");

pub const max_input_bytes: usize = 4096;
pub const max_key_material_bytes: usize = 128;

pub const MutationClass = enum {
    header_byte,
    payload_byte,
    footer_byte,
    authenticator_byte,
    extra_segment,
};

pub const PbkwV4FuzzParams: paseto.paserk.pbkw.V4Params = .{
    .memlimit_bytes = 8192,
    .opslimit = 1,
    .para = 1,
};
pub const PbkwV3FuzzParams: paseto.paserk.pbkw.V3Params = .{ .iterations = 1000 };

pub fn pickMutation(s: *std.testing.Smith) MutationClass {
    return s.value(MutationClass);
}

/// Returns an allocator-owned mutated token. Mutates via a parse→flip→serialize
/// round-trip so base64 fields stay legal. Caller frees the returned buffer.
pub fn mutateToken(
    allocator: std.mem.Allocator,
    token_str: []const u8,
    class: MutationClass,
    s: *std.testing.Smith,
) ![]u8 { /* implementation per spec */ }

/// Generic "is this error from the allowed set?" helper. Harnesses call
/// this in catch branches and let any unexpected error escape as a fuzz bug.
pub fn expectAllowed(
    err: anyerror,
    allowed: []const paseto.Error,
) !void {
    for (allowed) |a| if (err == a) return;
    std.debug.print("unexpected fuzz error: {t}\n", .{err});
    return error.UnexpectedFuzzError;
}
```

- [ ] **Step 3: Add `.gitkeep` files for corpus and regression directories**

Create:
- `tests/fuzz/corpus/.gitkeep` (empty file)
- `tests/fuzz/regressions/.gitkeep` (empty file)

Per-harness subdirectories get created in their respective tasks.

- [ ] **Step 4: Wire the fuzz graph into `build.zig`**

Add after the existing `test_step` block:

```zig
const fuzz_all_step = b.step("fuzz-all", "Run the full fuzz suite (seed-only without --fuzz)");
const fuzz_parsers_step = b.step("fuzz-parsers", "Run parser-group fuzz harnesses");
const fuzz_envelopes_step = b.step("fuzz-envelopes", "Run envelope-group fuzz harnesses");
const fuzz_scenarios_step = b.step("fuzz-scenarios", "Run scenario-group fuzz harnesses");
```

Introduce a helper local to `build.zig`:

```zig
fn addFuzzHarness(
    b: *std.Build,
    paseto_mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    comptime name: []const u8,
    comptime rel_path: []const u8,
    group_step: *std.Build.Step,
    all_step: *std.Build.Step,
) void {
    const mod = b.createModule(.{
        .root_source_file = b.path(rel_path),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("paseto", paseto_mod);
    const t = b.addTest(.{ .root_module = mod });
    const run = b.addRunArtifact(t);
    group_step.dependOn(&run.step);
    all_step.dependOn(&run.step);

    const own = b.step("fuzz-" ++ name, "Run the " ++ name ++ " fuzz harness");
    own.dependOn(&run.step);
}
```

In this task, only wire `support.zig` consumers via a single placeholder harness file `tests/fuzz/_placeholder.zig`:

```zig
test "fuzz scaffolding placeholder" {
    _ = @import("support.zig");
}
```

…so the graph compiles before the real harnesses land. Subsequent tasks replace/add to the list.

- [ ] **Step 5: Verify the scaffold compiles**

Run:
- `zig build --help`
- `zig build fuzz-all`

Expected:
- `fuzz-all`, `fuzz-parsers`, `fuzz-envelopes`, `fuzz-scenarios` appear in the help output.
- `zig build fuzz-all` succeeds with zero iterations (no real harnesses yet).

Also re-run `zig build test` to confirm the existing suite still passes.

- [ ] **Step 6: Commit**

```bash
git add tests/fuzz build.zig
git commit -m "test: scaffold built-in fuzz suite"
```

---

### Task 2: Parser Harnesses

**Files:**
- Create: `tests/fuzz/token.zig`
- Create: `tests/fuzz/util.zig`
- Create: `tests/fuzz/claims.zig`
- Create: `tests/fuzz/pem.zig`
- Create: `tests/fuzz/paserk_keys.zig`
- Create: `tests/fuzz/corpus/token/`, `tests/fuzz/corpus/util/`, `tests/fuzz/corpus/claims/`, `tests/fuzz/corpus/pem/`, `tests/fuzz/corpus/paserk_keys/`
- Modify: `build.zig` (register the five parser harnesses with `fuzz-parsers`)

- [ ] **Step 1: Seed each corpus directory**

For each parser harness, drop 3–8 representative seeds under `tests/fuzz/corpus/<harness>/`:

- `token/` — a valid v3.local, v4.local, v3.public, v4.public token (pulled from `tests/vectors/v3.json` and `v4.json`), plus one with only a header, one with too many dots, one empty string.
- `util/` — one canonical base64url string of ≥32 bytes, one hex string of even length, one with a `=` pad, one with `+` / `/` characters.
- `claims/` — one valid JSON claims object (exp/nbf/iat populated), one non-object JSON, one with a bad timestamp, one with `iss` as a number.
- `pem/` — one valid Ed25519 public key PEM, one valid PKCS#8 Ed25519 seed PEM, one valid SEC1 P-384 ECPrivateKey, one with leading garbage, one with trailing garbage.
- `paserk_keys/` — one `k4.local` PASERK, one `k3.public`, one `k4.secret`, one with wrong-length body, one with bad prefix.

Store seeds as raw `.bin` files (no decoration). The harness uses `@embedFile` to load them.

- [ ] **Step 2: Implement `tests/fuzz/token.zig`**

Shape:

```zig
const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const corpus = [_][]const u8{
    @embedFile("corpus/token/v4_local_valid.bin"),
    // ...more entries
};

const allowed_parse_errors = [_]paseto.Error{
    .InvalidToken, .UnsupportedVersion, .UnsupportedPurpose,
    .InvalidBase64, .InvalidPadding, .OutOfMemory,
};

test "fuzz: token.parse never panics" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, s: *std.testing.Smith) anyerror!void {
            var buf: [support.max_input_bytes]u8 = undefined;
            const n = s.slice(&buf);
            const input = buf[0..n];

            var tok = paseto.token.parse(std.testing.allocator, input) catch |err| {
                try support.expectAllowed(err, &allowed_parse_errors);
                return;
            };
            defer tok.deinit();

            // Invariant: round-trip through serialize → parse preserves bytes.
            const reserialized = try paseto.token.serialize(
                std.testing.allocator, tok.version, tok.purpose, tok.payload, tok.footer,
            );
            defer std.testing.allocator.free(reserialized);
            var tok2 = try paseto.token.parse(std.testing.allocator, reserialized);
            defer tok2.deinit();
            try std.testing.expectEqualSlices(u8, tok.payload, tok2.payload);
            try std.testing.expectEqualSlices(u8, tok.footer, tok2.footer);
        }
    }.run, .{ .corpus = &corpus });
}
```

Cover the spec's coverage list: missing/extra dots, unsupported versions/purposes, malformed base64, valid+mutate.

- [ ] **Step 3: Implement `tests/fuzz/util.zig`**

Three sub-targets in one file:

1. `util.decodeBase64Alloc` — `{InvalidBase64, InvalidPadding, OutOfMemory}` tolerated; on success, re-encode and confirm round-trip equals normalized input.
2. `util.hexDecodeAlloc` — `{InvalidEncoding, OutOfMemory}` tolerated; successful decode + re-encode with `std.fmt.bytesToHex` must match lowercased input.
3. `util.preAuthEncodeAlloc` — generate ≤8 small parts with Smith's `sliceWeighted`, ensure no panic and total length matches formula. No error case.

- [ ] **Step 4: Implement `tests/fuzz/claims.zig`**

Two sub-targets:

1. `claims.parseIsoTimestamp` — generate a Smith-shaped UTF-8 string (bounded ≤ 64 bytes) and pass it as `.{ .string = s }`; tolerated `{InvalidTime}`.
2. `claims.Validator.validate` — generate a short JSON-like byte string (bounded ≤ 512 bytes); tolerated errors per the spec rejection contract for claims. On success, run `validate` twice with the same bytes and confirm both outcomes match.

Include a structured-generation path that assembles plausible JSON objects using Smith (pick 0–4 registered claims, fabricate timestamps from a known range, optional `iss` string, optional numeric `iss` for negative path).

- [ ] **Step 5: Implement `tests/fuzz/pem.zig`**

Two sub-targets:

1. `pem.pemToDer` — tolerated `{InvalidEncoding, InvalidBase64, OutOfMemory}`.
2. `pem.parse` — tolerated `{InvalidEncoding, InvalidBase64, InvalidKey, UnsupportedVersion, OutOfMemory}`.

Structured seeds: concatenate two valid PEM blocks, truncate one in the middle, flip a single character in the base64 body.

- [ ] **Step 6: Implement `tests/fuzz/paserk_keys.zig`**

One sub-target: `paserk.keys.parse`. Tolerated `{InvalidEncoding, UnsupportedVersion, UnsupportedOperation, InvalidKey, InvalidBase64, InvalidPadding, OutOfMemory}`.

Round-trip invariant: when parse succeeds, `serialize(parsed.version, parsed.kind, parsed.bytes)` must equal the normalized input (reject leading/trailing whitespace before the check — PASERK strings do not contain whitespace, so the harness asserts byte-for-byte equality).

- [ ] **Step 7: Register the five parser harnesses in `build.zig`**

Remove the placeholder harness. Register each via the `addFuzzHarness` helper, attached to `fuzz_parsers_step` and `fuzz_all_step`, with per-harness steps `fuzz-token`, `fuzz-util`, `fuzz-claims`, `fuzz-pem`, `fuzz-paserk_keys`.

- [ ] **Step 8: Seed-only verification**

Run each harness individually first, then the group:

```
zig build fuzz-token
zig build fuzz-util
zig build fuzz-claims
zig build fuzz-pem
zig build fuzz-paserk_keys
zig build fuzz-parsers
```

Expected: all pass.

- [ ] **Step 9: Full-suite verification**

Run: `zig build test && zig build fuzz-all`

Expected: both green.

- [ ] **Step 10: Commit**

```bash
git add tests/fuzz/token.zig tests/fuzz/util.zig tests/fuzz/claims.zig tests/fuzz/pem.zig tests/fuzz/paserk_keys.zig tests/fuzz/corpus/ tests/fuzz/regressions/ build.zig
git commit -m "test: add parser fuzz harnesses"
```

---

### Task 3: Envelope Harnesses

**Files:**
- Create: `tests/fuzz/paserk_pie.zig`
- Create: `tests/fuzz/paserk_pke.zig`
- Create: `tests/fuzz/paserk_pbkw.zig`
- Create: `tests/fuzz/paserk_id.zig`
- Create: corresponding `corpus/<harness>/` dirs with 3–6 seeds each
- Modify: `build.zig` (register under `fuzz-envelopes`)

- [ ] **Step 1: Seed the corpora from official PASERK vectors**

For each harness, pick seeds from `tests/vectors/`:
- `paserk_pie/` — valid `k3.local-wrap.pie.*`, `k3.secret-wrap.pie.*`, `k4.local-wrap.pie.*`, `k4.secret-wrap.pie.*` from the `.pie.json` files, plus a truncated and tag-flipped variant.
- `paserk_pke/` — a `k4.seal.*` and `k3.seal.*` from `.seal.json`, plus a short-body case.
- `paserk_pbkw/` — a `k3.local-pw.*`, `k4.local-pw.*`, `k3.secret-pw.*`, `k4.secret-pw.*` from the `.*-pw.json` files.
- `paserk_id/` — raw key material bytes (not PASERK strings) at valid lengths so the harness can compute `lid`/`sid`/`pid`.

- [ ] **Step 2: Implement `tests/fuzz/paserk_pie.zig`**

Three sub-targets in one file:

1. `pie.unwrap` — Smith produces a bounded PASERK-shaped string; tolerated `{InvalidEncoding, UnsupportedVersion, UnsupportedOperation, InvalidKey, InvalidAuthenticator, MessageTooShort, InvalidBase64, InvalidPadding, OutOfMemory}`.
2. Round-trip — Smith produces a wrapping key + ptk; wrap and unwrap; expect exact byte recovery.
3. Mutation reject — wrap a valid ptk, mutate one byte inside the base64 body (via decode→flip→re-encode), expect `InvalidAuthenticator` or structured rejection from the allowed set.

- [ ] **Step 3: Implement `tests/fuzz/paserk_pke.zig`**

Four sub-targets: `unsealV3`, `unsealV4`, `unsealV4FromSecretKey`, plus seal/unseal round-trip and mutation reject. Tolerated: `{InvalidEncoding, InvalidKey, InvalidAuthenticator, MessageTooShort, InvalidBase64, InvalidPadding, OutOfMemory}`.

For round-trip, use fixed recipient keys generated at test-start (`paseto.v4.Public.generate()` seed + `paseto.v3.Public.generate()` seed fixed in the harness) so runs are deterministic across iterations.

- [ ] **Step 4: Implement `tests/fuzz/paserk_pbkw.zig`**

Three sub-targets:

1. `unwrap` — tolerated `{InvalidEncoding, UnsupportedVersion, UnsupportedOperation, InvalidKey, InvalidAuthenticator, MessageTooShort, WeakParameters, Canceled, OutOfMemory, InvalidBase64, InvalidPadding}`.
2. `wrapV4` / `wrapV3` with **`support.PbkwV4FuzzParams` / `PbkwV3FuzzParams`** — tolerated `{InvalidKey, WeakParameters, Canceled, OutOfMemory}`. Do NOT feed `memlimit_bytes` from Smith; the scenario family / round-trip sub-target must use the bounded constants.
3. Round-trip — wrap, unwrap; expect byte recovery.

Add one targeted negative sub-target that feeds `memlimit_bytes = 1500` to `wrapV4` and asserts `Error.WeakParameters`. This preserves Task 3 of the prior remediation plan.

- [ ] **Step 5: Implement `tests/fuzz/paserk_id.zig`**

Three sub-targets across `lid`, `sid`, `pid`:

1. Valid length → success; repeated calls on same input yield identical output; result starts with expected `k3.lid.` / `k4.sid.` / `k4.pid.` etc prefix for the chosen version/kind.
2. Wrong length → `InvalidKey`.
3. Structured fuzz of `compute(version, kind, bytes)`: tolerated `{InvalidKey, OutOfMemory}`.

- [ ] **Step 6: Register the four envelope harnesses**

Via `addFuzzHarness` under `fuzz_envelopes_step` and `fuzz_all_step`, plus per-harness steps `fuzz-paserk_pie`, `fuzz-paserk_pke`, `fuzz-paserk_pbkw`, `fuzz-paserk_id`.

- [ ] **Step 7: Verification**

```
zig build fuzz-paserk_pie
zig build fuzz-paserk_pke
zig build fuzz-paserk_pbkw
zig build fuzz-paserk_id
zig build fuzz-envelopes
zig build fuzz-all
```

Expected: all pass seed-only (generative fuzz is blocked by the 0.16.0 test-runner defect).

- [ ] **Step 8: Commit**

```bash
git add tests/fuzz/paserk_pie.zig tests/fuzz/paserk_pke.zig tests/fuzz/paserk_pbkw.zig tests/fuzz/paserk_id.zig tests/fuzz/corpus/ build.zig
git commit -m "test: add envelope fuzz harnesses"
```

---

### Task 4: High-Level API Harnesses

**Files:**
- Create: `tests/fuzz/v4_local.zig`
- Create: `tests/fuzz/v4_public.zig`
- Create: `tests/fuzz/v3_local.zig`
- Create: `tests/fuzz/v3_public.zig`
- Create: corpus subdirs
- Modify: `build.zig`

- [ ] **Step 1: Seed corpora**

For each of the four harnesses, drop 3–6 tokens pulled directly from `tests/vectors/v3.json` and `tests/vectors/v4.json` — one per `name` entry at minimum: `4-E-1`, `4-S-1`, `3-E-1`, `3-S-1`, plus one tampered variant per file.

- [ ] **Step 2: Implement `tests/fuzz/v4_local.zig`**

Sub-targets:

1. `decrypt` on Smith-generated bytes — tolerated `{InvalidToken, WrongPurpose, InvalidAuthenticator, MessageTooShort, InvalidKey, InvalidBase64, InvalidPadding, UnsupportedVersion, UnsupportedPurpose, OutOfMemory}`.
2. Round-trip: generate a key once, `encrypt` Smith-shaped message + footer + assertion, then `decrypt`, expect byte-for-byte recovery.
3. Mutation reject: take a round-trip token and apply `support.mutateToken` with a Smith-chosen `MutationClass`, expect failure with an allowed error.

Use `support.max_input_bytes / 2` as the upper bound for message + footer + assertion sizes combined.

- [ ] **Step 3: Implement `tests/fuzz/v4_public.zig`**

Sub-targets mirroring `v4_local` but around `sign`/`verify`. Tolerated verify errors: `{InvalidToken, WrongPurpose, InvalidSignature, InvalidKey, InvalidKeyPair, MessageTooShort, InvalidBase64, InvalidPadding, UnsupportedVersion, UnsupportedPurpose, OutOfMemory}`.

Add constructor mis-use sub-target: feed Smith bytes to `Public.fromSeed` / `fromPublicKeyBytes` / `fromSecretKeyBytes`; tolerated `{InvalidKey, InvalidKeyPair, OutOfMemory}`.

- [ ] **Step 4: Implement `tests/fuzz/v3_local.zig`**

Mirror `v4_local`, but use `paseto.v3.Local`. Same allowed error lists.

- [ ] **Step 5: Implement `tests/fuzz/v3_public.zig`**

Mirror `v4_public`, but include `Public.fromPublicBytesCompressed` / `fromPublicBytesUncompressed` / `fromScalarBytes` constructor fuzzing. Tolerated constructor errors: `{InvalidKey, InvalidKeyPair, OutOfMemory}`.

- [ ] **Step 6: Register the four harnesses**

Under `fuzz_envelopes_step` (per the spec grouping — HL API harnesses verify envelope boundaries). Per-harness steps: `fuzz-v4_local`, `fuzz-v4_public`, `fuzz-v3_local`, `fuzz-v3_public`.

- [ ] **Step 7: Verification**

```
zig build fuzz-v4_local
zig build fuzz-v4_public
zig build fuzz-v3_local
zig build fuzz-v3_public
zig build fuzz-envelopes
```

Seed-only green is the bar until the 0.16.0 test-runner defect clears.

- [ ] **Step 8: Commit**

```bash
git add tests/fuzz/v4_local.zig tests/fuzz/v4_public.zig tests/fuzz/v3_local.zig tests/fuzz/v3_public.zig tests/fuzz/corpus/ build.zig
git commit -m "test: add high-level api fuzz harnesses"
```

---

### Task 5: Scenario Harness

**Files:**
- Create: `tests/fuzz/scenarios.zig`
- Create: `tests/fuzz/corpus/scenarios/` (5–10 seeds; each seed drives a specific family via the first Smith byte choosing the family tag)
- Modify: `build.zig` (register under `fuzz-scenarios`)

- [ ] **Step 1: Define the scenario grammar**

In `tests/fuzz/scenarios.zig` introduce:

```zig
const Family = enum {
    local_round_trip,
    public_round_trip,
    local_mutation_reject,
    public_mutation_reject,
    paserk_key_round_trip,
    pie_round_trip,
    pke_round_trip,
    pbkw_round_trip,
    mixed_version_misuse,
    mixed_purpose_misuse,
};

const MismatchClass = enum {
    wrong_version,
    wrong_purpose,
    wrong_key,
    mutated_payload,
    mutated_authenticator_or_signature,
    malformed_framing,
};
```

Each family implements exactly the operation sequence listed in the design doc; do not invent extra steps.

- [ ] **Step 2: Implement the scenario dispatch**

```zig
test "fuzz: scenario grammar" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, s: *std.testing.Smith) anyerror!void {
            const family = s.value(Family);
            switch (family) {
                .local_round_trip => try runLocalRoundTrip(s),
                .public_round_trip => try runPublicRoundTrip(s),
                .local_mutation_reject => try runLocalMutationReject(s),
                .public_mutation_reject => try runPublicMutationReject(s),
                .paserk_key_round_trip => try runPaserkKeyRoundTrip(s),
                .pie_round_trip => try runPieRoundTrip(s),
                .pke_round_trip => try runPkeRoundTrip(s),
                .pbkw_round_trip => try runPbkwRoundTrip(s),
                .mixed_version_misuse => try runMixedVersionMisuse(s),
                .mixed_purpose_misuse => try runMixedPurposeMisuse(s),
            }
        }
    }.run, .{ .corpus = &scenario_corpus });
}
```

Each `run...` helper:
- picks its variant via `s.value(Variant)` where Variant is a family-scoped enum
- populates only the state slots listed in the design's "Scenario-family preconditions" section
- performs exactly the operations listed in "Exact scenario families"
- asserts success-only invariants for round-trip families and allowed-failure sets for mutation/misuse families

- [ ] **Step 3: Implement round-trip families**

`local_round_trip`, `public_round_trip`, `paserk_key_round_trip`, `pie_round_trip`, `pke_round_trip`, `pbkw_round_trip` all assert success-only outcomes. Any error is a fuzz bug.

- [ ] **Step 4: Implement mutation-reject families**

`local_mutation_reject` and `public_mutation_reject` call their sibling round-trip helper, then apply `support.mutateToken` with a Smith-chosen `MutationClass`, then attempt decrypt/verify.

Allowed errors:
- local: `{InvalidToken, WrongPurpose, InvalidAuthenticator, MessageTooShort, InvalidBase64, InvalidPadding, UnsupportedVersion, UnsupportedPurpose}`
- public: `{InvalidToken, WrongPurpose, InvalidSignature, MessageTooShort, InvalidBase64, InvalidPadding, UnsupportedVersion, UnsupportedPurpose}`

A success after mutation is a fuzz bug.

- [ ] **Step 5: Implement misuse families**

`mixed_version_misuse`:
- produce a v3.local token, attempt decrypt via v4.Local
- produce a v4.local token, attempt decrypt via v3.Local
- etc. across local/public in both directions
- allowed: `{WrongPurpose, InvalidEncoding, UnsupportedVersion, UnsupportedPurpose, UnsupportedOperation, InvalidToken}`

`mixed_purpose_misuse`:
- produce a v4.local token, attempt verify via v4.Public
- produce a v4.public token, attempt decrypt via v4.Local
- produce a v3.local token, attempt verify via v3.Public
- produce a v3.public token, attempt decrypt via v3.Local
- allowed: `{WrongPurpose, InvalidToken}`

Record the exact `MismatchClass` in a local variable so a failing invariant assertion can print it for triage.

- [ ] **Step 6: Seed the scenario corpus**

Drop 5–10 small seeds at `tests/fuzz/corpus/scenarios/`. Each seed is essentially a Smith input stream: the first byte picks the `Family`, subsequent bytes feed the variant selectors and key material. Hand-crafted seeds ensure every family is hit at least once without the fuzz engine.

- [ ] **Step 7: Register the scenario harness**

Attach to `fuzz_scenarios_step` and `fuzz_all_step`, plus a per-harness step `fuzz-scenarios` (singular).

- [ ] **Step 8: Verification**

```
zig build fuzz-scenarios
zig build fuzz-all
```

Seed-only green (generative fuzz blocked by 0.16.0 test-runner defect).

- [ ] **Step 9: Commit**

```bash
git add tests/fuzz/scenarios.zig tests/fuzz/corpus/scenarios build.zig
git commit -m "test: add cross-module scenario fuzz harness"
```

---

### Task 6: Corpus, Regressions, and Developer UX Polish

**Files:**
- Modify: `README.md`
- Modify: `.gitignore` (add `tests/fuzz/corpus/_gen/` if any generator writes there)
- Optional modify: `build.zig` (polish step descriptions)

- [ ] **Step 1: Document the fuzz workflow**

Add a "Fuzzing" section to `README.md` covering:

- what it is (local, developer-invoked, built-in engine only)
- how to run it: `zig build fuzz-all`, `zig build fuzz-parsers --fuzz`, `zig build fuzz-envelopes --fuzz=1G`, `zig build fuzz-all --fuzz --webui`
- how to reproduce a specific harness after a crash: `zig build fuzz-<name> --fuzz=<limit>`
- corpus policy: seeds live at `tests/fuzz/corpus/<harness>/`; anything the fuzzer itself writes lives in the Zig cache and must not be checked in
- regression policy: every confirmed crash from a long run becomes either a corpus seed at `tests/fuzz/corpus/<harness>/` or a deterministic test (unit or fuzz-with-corpus-only) under `tests/fuzz/regressions/<harness>/`
- performance guidance for long runs: invoke group steps in separate terminals to saturate cores (`fuzz-parsers` + `fuzz-envelopes` + `fuzz-scenarios` in parallel)

- [ ] **Step 2: Sanity-check `zig build --help`**

Confirm the fuzz steps are self-describing:

```
fuzz-all         Run the full fuzz suite (seed-only without --fuzz)
fuzz-parsers     Run parser-group fuzz harnesses
fuzz-envelopes   Run envelope-group fuzz harnesses
fuzz-scenarios   Run scenario-group fuzz harnesses
fuzz-token       ...
fuzz-util        ...
...
```

Adjust descriptions if any feel stale.

- [ ] **Step 3: Final verification**

```
zig build test
zig build fuzz-all
```

Both green.

- [ ] **Step 4: Commit**

```bash
git add README.md build.zig .gitignore
git commit -m "docs: document local fuzz workflow and regression policy"
```

---

## Definition Of Done

- `tests/fuzz/` hosts 13 harnesses plus a shared support module and per-harness corpora.
- `zig build fuzz-all` passes in seed-only mode.
- `zig build fuzz-<name>` works for each of the 13 harnesses as a targeted repro entrypoint.
- `zig build fuzz-parsers`, `zig build fuzz-envelopes`, `zig build fuzz-scenarios`, `zig build fuzz-all` all accept `--fuzz[=limit]` and `--webui`.
- No production `src/` files are modified by this plan beyond tightly-scoped fuzz-only helpers (none expected).
- `README.md` documents the fuzz workflow, corpus policy, and regression policy.
- Harness error contracts match the spec's rejection-contract table verbatim.
- Scenario harness covers all 10 families from the spec with the operation counts the spec mandates.
- `zig build test` continues to pass at the end of each merged workstream.

## Verification Matrix

- Scaffold compile loop:
  - `zig build --help`
  - `zig build fuzz-all`
- Per-task checks (after Task 2 onward):
  - `zig build fuzz-<harness>` seed-only
  - `zig build fuzz-<harness> --fuzz=<100K or less> ` short bounded spike
- Regression verification for any promoted crash:
  - `zig build fuzz-<harness>` (seed-only; regression is in the embedded corpus)
- Full-suite regression:
  - `zig build test`
  - `zig build fuzz-all`

## Handoff Notes For The Next Agent

- Start with Task 1 (scaffolding) — do not start writing harnesses before the build graph and support module compile.
- If a harness triggers an error not in the spec's rejection contract, STOP and file drift to the user rather than broadening the allowed set. The contract is a design constraint, not a ceiling.
- The scenario harness is the biggest risk surface for non-determinism. Keep it strictly within the 10 families listed in the design doc; do not invent workflows.
- Budget ≤ 60s of wall-clock fuzz time per harness during implementation; rely on the developer-led 48h run for deep coverage.
- Do not add `.fuzz = true` on modules — rely on the CLI `--fuzz` flag.
- Keep seed corpus small (~3–10 files per harness). Bulk growth is the fuzz engine's job, not a manual one.
- If `-ffuzz` is broken on the developer's platform, surface that rather than writing elaborate workarounds — Zig's CLI fuzz story is the only tool we commit to in this design.
