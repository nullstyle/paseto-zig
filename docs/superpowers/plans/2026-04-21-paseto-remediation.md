# Paseto Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden correctness, security-sensitive parsing, test depth, and contributor workflow for `paseto-zig` without changing supported wire formats or public feature scope.

**Architecture:** Treat this as four ordered workstreams: claims validation hardening, PEM/DER strictness, test-harness strengthening, and repo/DX cleanup. Do not start with refactors; first close correctness bugs behind focused tests, then tighten parsing and verification, then improve maintainability and contributor ergonomics.

**Tech Stack:** Zig `0.16.0`, `std.crypto`, `std.json`, `std.base64`, `std.Build`, PASETO/PASERK test vectors

---

## Context Snapshot

- Current suite status: `zig build test` passes in this checkout.
- Highest-risk issues are in security-sensitive validation/parsing, not baseline functionality.
- The repository is still early-stage operationally: no commits on `main`, no root `.gitignore`, no visible CI, and the vendored Ruby reference is an SSH submodule.

## Guardrails For The Implementing Agent

- Preserve supported PASETO/PASERK behavior and vector compatibility.
- Prefer narrowly-scoped fixes with tests over broad refactors.
- Do not change cryptographic constructions unless a spec violation is proven.
- Keep the vendored Ruby tree read-only unless a task explicitly says otherwise.
- Use TDD for each task: failing test first, then minimal implementation, then verification.
- Commit after each task or logically-complete cluster.

## File Map

- Modify: `src/claims.zig`
  Purpose: Registered-claim validation, ISO-8601 parsing, required-claim behavior.
- Modify: `src/pem.zig`
  Purpose: PEM detection, DER walking, strict AlgorithmIdentifier / PKCS#8 / SPKI validation.
- Modify: `src/paserk/pbkw.zig`
  Purpose: PBKW parameter validation and clearer error handling.
- Modify: `tests/e2e.zig`
  Purpose: High-level negative-path tests at the public API boundary.
- Modify: `tests/vectors.zig`
  Purpose: Make vector harness fail closed instead of silently skipping unrecognized cases.
- Modify: `README.md`
  Purpose: Accurate install instructions, compatibility statement, contributor workflow, and vendor policy.
- Modify: `build.zig`
  Purpose: Add faster focused test entrypoints for developer workflow.
- Create: `.gitignore`
  Purpose: Keep generated Zig state out of `git status`.
- Modify: `.gitmodules`
  Purpose: Reduce clone friction if the vendor submodule remains.
- Optional modify: `src/token.zig`, `src/paserk/keys.zig`, `src/pem.zig`, `src/claims.zig`
  Purpose: Ownership-footgun documentation or follow-up ergonomics once correctness tasks are complete.

## Recommended Execution Order

1. Claims validation hardening
2. PEM/DER strictness hardening
3. PBKW parameter validation
4. Negative-path and harness coverage
5. Developer-experience cleanup
6. Optional maintainability follow-up

---

### Task 1: Fix Claim Validation Correctness

**Files:**
- Modify: `src/claims.zig`
- Test: `src/claims.zig`
- Test: `tests/e2e.zig`

- [ ] **Step 1: Add failing timestamp-validation tests in `src/claims.zig`**

```zig
test "ISO8601 parsing rejects impossible calendar dates and out-of-range times" {
    try std.testing.expectError(Error.InvalidTime, parseIsoTimestamp(.{ .string = "2022-02-31T00:00:00Z" }));
    try std.testing.expectError(Error.InvalidTime, parseIsoTimestamp(.{ .string = "2024-02-30T00:00:00Z" }));
    try std.testing.expectError(Error.InvalidTime, parseIsoTimestamp(.{ .string = "2022-01-01T24:00:00Z" }));
    try std.testing.expectError(Error.InvalidTime, parseIsoTimestamp(.{ .string = "2022-01-01T23:60:00Z" }));
    try std.testing.expectError(Error.InvalidTime, parseIsoTimestamp(.{ .string = "2022-01-01T23:59:60Z" }));
}

test "validator rejects required claims with wrong JSON types" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.InvalidIssuer, (.{
        .require_issuer = true,
        .now_override = 1_700_000_000,
    }: Validator).validate("{\"iss\":123}", allocator));
    try std.testing.expectError(Error.InvalidAudience, (.{
        .require_audience = true,
        .now_override = 1_700_000_000,
    }: Validator).validate("{\"aud\":false}", allocator));
    try std.testing.expectError(Error.InvalidSubject, (.{
        .require_subject = true,
        .now_override = 1_700_000_000,
    }: Validator).validate("{\"sub\":1}", allocator));
    try std.testing.expectError(Error.InvalidTokenIdentifier, (.{
        .require_token_identifier = true,
        .now_override = 1_700_000_000,
    }: Validator).validate("{\"jti\":{}}", allocator));
}
```

- [ ] **Step 2: Run the focused claims tests and confirm they fail**

Run: `zig test src/claims.zig`

Expected: FAIL on impossible-date acceptance and required-claim type handling.

- [ ] **Step 3: Implement strict timestamp range validation**

Implementation notes:
- Add explicit range checks for hour `< 24`, minute `< 60`, second `< 60`.
- Replace the current `day <= 31` check with month-aware validation.
- Handle leap years correctly for February.
- Keep accepted formats unchanged:
  - `YYYY-MM-DDTHH:MM:SS(.fff)?Z`
  - `YYYY-MM-DDTHH:MM:SS(.fff)?±HH:MM`
  - `YYYY-MM-DDTHH:MM:SS(.fff)?±HHMM`
  - the same forms with a single space instead of `T`
- This task must preserve support for both offset spellings because the current parser accepts both.

Suggested helper shape:

```zig
fn isLeapYear(y: i32) bool {
    return (y % 4 == 0 and y % 100 != 0) or (y % 400 == 0);
}

fn maxDayInMonth(y: i32, m: u8) Error!u8 {
    return switch (m) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(y)) 29 else 28,
        else => Error.InvalidTime,
    };
}
```

- [ ] **Step 4: Tighten required-claim behavior**

Implementation notes:
- In the `else if (self.require_issuer)` style branches, reject present-but-wrong-type values, not just missing values.
- Apply the same rule for `iss`, `aud`, `sub`, and `jti`.
- Keep current behavior for `expected_*` branches.
- Preserve the current library contract that `aud` is a JSON string in this implementation.
- Do not broaden `aud` handling to arrays in this task; reject non-string `aud` values consistently in both expected and required branches.

- [ ] **Step 5: Add one high-level regression test in `tests/e2e.zig`**

```zig
test "claims validator rejects malformed required claims" {
    const allocator = std.testing.allocator;
    const validator: paseto.Validator = .{
        .require_issuer = true,
        .now_override = 1_700_000_000,
    };
    try std.testing.expectError(paseto.Error.InvalidIssuer, validator.validate("{\"iss\":1}", allocator));
}
```

- [ ] **Step 6: Re-run claims and full-suite verification**

Run: `zig test src/claims.zig`

Expected: PASS

Run: `zig build test`

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/claims.zig tests/e2e.zig
git commit -m "fix: harden claim timestamp and type validation"
```

---

### Task 2: Tighten PEM And DER Parsing

**Files:**
- Modify: `src/pem.zig`
- Test: `src/pem.zig`

- [ ] **Step 1: Add failing strictness tests in `src/pem.zig`**

Add tests for:
- Garbage before `-----BEGIN ...-----`
- Garbage after `-----END ...-----`
- Concatenated second PEM block after a valid one
- Valid DER object with trailing bytes
- AlgorithmIdentifier / PKCS#8 / SPKI sequences containing trailing elements

Minimal examples:

```zig
test "pemToDer rejects leading and trailing garbage" {
    const allocator = std.testing.allocator;
    const pem =
        \\junk
        \\-----BEGIN PUBLIC KEY-----
        \\MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=
        \\-----END PUBLIC KEY-----
    ;
    try std.testing.expectError(Error.InvalidEncoding, parse(allocator, pem));
}
```

- [ ] **Step 2: Run PEM-focused tests and confirm failure**

Run: `zig test src/pem.zig`

Expected: FAIL on permissive parsing cases.

- [ ] **Step 3: Make PEM framing strict**

Implementation notes:
- `Label.detect` should not accept a begin marker from the middle of the input.
- Adopt this exact framing policy:
  - allow only ASCII whitespace (`' '`, `'\t'`, `'\r'`, `'\n'`) before the begin tag
  - allow only ASCII whitespace after the end tag
  - reject any other leading or trailing bytes
- Require the first non-whitespace byte of the file to begin the expected PEM header.
- Reject non-whitespace content before the begin tag and after the end tag.
- Keep whitespace stripping inside the base64 body, but only inside the framed body.

- [ ] **Step 4: Make DER sequence consumption strict**

Implementation notes:
- Add helpers that assert `rest.len == 0` when a structure is supposed to be fully consumed.
- Apply this to `parseAlgorithmIdentifier`, `parsePkcs8PrivateKey`, `parseSpki`, and `parseSec1EcPrivateKey`.
- Enforce this exact acceptance matrix:
  - Ed25519 `AlgorithmIdentifier` must be exactly a SEQUENCE containing only OID `1.3.101.112`, with no parameters and no trailing elements.
  - P-384 `AlgorithmIdentifier` must be exactly a SEQUENCE containing OID `1.2.840.10045.2.1` plus OID `1.3.132.0.34`, with no extra parameters and no trailing elements.
  - `SEC1 ECPrivateKey`, `PKCS#8 PrivateKeyInfo`, and `SubjectPublicKeyInfo` must each consume their full enclosing SEQUENCE with no trailing bytes.
  - `BIT STRING` payloads must still require zero unused bits.
- Remove `buildOidEncoded` if a clearer OID parsing approach is available.
- Avoid pointer-arithmetic assumptions tied to short-form length encoding.

- [ ] **Step 5: Re-run PEM and full-suite verification**

Run: `zig test src/pem.zig`

Expected: PASS

Run: `zig build test`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/pem.zig
git commit -m "fix: reject permissive pem and der inputs"
```

---

### Task 3: Validate PBKW Parameters More Strictly

**Files:**
- Modify: `src/paserk/pbkw.zig`
- Test: `src/paserk/pbkw.zig`

- [ ] **Step 1: Add failing PBKW parameter tests**

Add tests for:
- `memlimit_bytes` smaller than 1024
- `memlimit_bytes` not divisible by 1024
- `opslimit == 0`
- `para != 1`
- stable mapping for non-parameter Argon2 runtime failures

Example shape:

```zig
test "wrapV4 rejects non-kib-aligned memlimit_bytes" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x11} ** 32;
    try std.testing.expectError(Error.WeakParameters, wrapV4(allocator, .local, "pw", &key, .{
        .params = .{ .memlimit_bytes = 1500, .opslimit = 2 },
        .salt = [_]u8{0x22} ** 16,
        .nonce = [_]u8{0x33} ** 24,
    }));
}
```

- [ ] **Step 2: Run the PBKW-focused tests and confirm failure**

Run: `zig test src/paserk/pbkw.zig`

Expected: FAIL because the current implementation truncates bytes to KiB.

- [ ] **Step 3: Add explicit parameter validation before Argon2 invocation**

Implementation notes:
- Reject `memlimit_bytes < 1024`.
- Reject `memlimit_bytes % 1024 != 0`.
- Reject `opslimit == 0`.
- Reject any `para` value other than `1`, because PASERK fixes the parallelism factor at `1`.
- Return `Error.WeakParameters` for caller mistakes.

- [ ] **Step 4: Improve error mapping conservatively**

Implementation notes:
- Keep the public behavior deterministic:
  - caller-supplied parameter mistakes must return `Error.WeakParameters`
  - `error.Canceled` must keep mapping to `Error.Canceled`
  - all remaining Argon2 runtime failures should continue mapping to `Error.OutOfMemory`
- Do not invent new public error cases in this task.
- Add a short comment near the catch block explaining that non-parameter Argon2 failures are intentionally collapsed to `Error.OutOfMemory` because the current public error set does not distinguish them.

- [ ] **Step 5: Re-run PBKW and full-suite verification**

Run: `zig test src/paserk/pbkw.zig`

Expected: PASS

Run: `zig build test`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/paserk/pbkw.zig
git commit -m "fix: validate pbkw argon2 parameters explicitly"
```

---

### Task 4: Make Vector And E2E Coverage Fail Closed

**Files:**
- Modify: `tests/vectors.zig`
- Modify: `tests/e2e.zig`

- [ ] **Step 1: Add failing tests or assertions for skipped vector cases**

Implementation notes:
- For top-level dispatch, fail when a vector name prefix is unknown instead of silently ignoring it.
- In inner loops, replace ambiguous `continue` branches with explicit assertions when the input shape is unexpected for a file that claims to be authoritative.
- Preserve intentional wrong-version negative cases, but make the reason for acceptance vs rejection explicit.

- [ ] **Step 2: Add negative-path e2e tests**

Add tests for:
- wrong implicit assertion rejected
- modified footer or payload rejected
- wrong key rejected
- malformed token string rejected

Example shape:

```zig
test "v4.local rejects wrong implicit assertion" {
    const allocator = std.testing.allocator;
    const key = paseto.v4.Local.generate();
    const tok = try key.encrypt(allocator, "hello", .{ .implicit_assertion = "a" });
    defer allocator.free(tok);
    try std.testing.expectError(paseto.Error.InvalidAuthenticator, key.decrypt(allocator, tok, "b"));
}
```

- [ ] **Step 3: Run the modified tests and confirm failure before implementation**

Run: `zig build test`

Expected: FAIL because the current harness still skips or because negative-path coverage is missing.

- [ ] **Step 4: Implement fail-closed harness behavior in `tests/vectors.zig`**

Implementation notes:
- Unknown vector categories should fail loudly.
- Unexpected field shapes in official vector files should fail loudly unless a specific case is intentionally documented.
- Consider adding counters so each test file proves it executed at least one vector.

- [ ] **Step 5: Re-run full verification**

Run: `zig build test`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add tests/vectors.zig tests/e2e.zig
git commit -m "test: strengthen vector harness and negative-path coverage"
```

---

### Task 5: Improve Contributor Workflow And Repo Hygiene

**Files:**
- Create: `.gitignore`
- Modify: `build.zig`
- Modify: `README.md`
- Modify: `.gitmodules`

- [ ] **Step 1: Add `.gitignore` for generated Zig artifacts**

Suggested contents:

```gitignore
.zig-cache/
zig-out/
```

- [ ] **Step 2: Add focused build steps for faster feedback**

Implementation notes for `build.zig`:
- Keep existing `test` step unchanged.
- Add narrow steps such as:
  - `unit` for source-embedded tests
  - `vectors` for `tests/vectors.zig`
  - `e2e` for `tests/e2e.zig`
- Keep descriptions clear so `zig build --help` becomes useful onboarding documentation.

- [ ] **Step 3: Update README for real installation and workflow guidance**

Implementation notes:
- Replace placeholder dependency instructions or clearly mark them as TODO if publish metadata does not exist yet.
- Use `0.16.0` as the canonical Zig version string in user-facing docs, matching the local verified compiler and `build.zig.zon`.
- Do not leave `0.16.0-dev` in the README unless you also prove the code requires unreleased Zig behavior and update `build.zig.zon` to match in the same commit.
- Add a short “Contributing” section with:
  - `zig build unit`
  - `zig build vectors`
  - `zig build e2e`
  - `zig build test`
- Explain that `vendor/ruby/` is reference-only and should not be edited as part of normal Zig changes.

- [ ] **Step 4: Reduce submodule friction**

Pick one of these and document the choice in the commit message:
- Preferred: switch `.gitmodules` to HTTPS URL.
- Alternative: remove the submodule entirely if the project wants a plain vendored snapshot instead.

- [ ] **Step 5: Verify the workflow changes**

Run:
- `zig build --help`
- `zig build unit`
- `zig build vectors`
- `zig build e2e`
- `zig build test`
- `git status --short`

Expected:
- New steps appear in build help.
- All test steps pass.
- `.zig-cache/` is no longer reported as untracked noise.

- [ ] **Step 6: Commit**

```bash
git add .gitignore build.zig README.md .gitmodules
# If keeping the submodule:
git commit -m "docs: improve contributor workflow and switch vendor submodule to https"

# If removing the submodule:
git commit -m "docs: improve contributor workflow and simplify vendor policy"
```

---

### Task 6: Optional Maintainability Follow-Up

**Files:**
- Optional modify: `src/token.zig`
- Optional modify: `src/claims.zig`
- Optional modify: `src/pem.zig`
- Optional modify: `src/paserk/keys.zig`
- Optional modify: `src/v3/local.zig`
- Optional modify: `src/v4/local.zig`
- Optional modify: `src/v3/public.zig`
- Optional modify: `src/v4/public.zig`

- [ ] **Step 1: Decide whether to defer this task**

Only do this after Tasks 1-5 are merged and green.

- [ ] **Step 2: Reduce ownership-footgun risk**

Options:
- Add prominent doc comments warning that owner structs must not be copied after `deinit`.
- Or introduce a safer pattern only if it stays idiomatic for this codebase.

Relevant sites:
- `src/token.zig`
- `src/claims.zig`
- `src/pem.zig`
- `src/paserk/keys.zig`

- [ ] **Step 3: Evaluate localized deduplication**

Targets:
- shared helper extraction for v3/v4 wrapper lifecycle
- shared token assembly / verification scaffolding

Rules:
- No behavior changes
- No large refactor in the same commit as security fixes
- Abort if the abstraction starts obscuring protocol differences

- [ ] **Step 4: Verify unchanged behavior**

Run: `zig build test`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/token.zig src/claims.zig src/pem.zig src/paserk/keys.zig src/v3/local.zig src/v4/local.zig src/v3/public.zig src/v4/public.zig
git commit -m "refactor: reduce ownership and duplication footguns"
```

---

## Definition Of Done

- Claims validation rejects impossible timestamps and wrong-type required claims.
- PEM parsing rejects garbage-prefixed, garbage-suffixed, concatenated, and DER-trailing inputs.
- PBKW v4 rejects non-KiB-aligned or obviously weak Argon2 memory parameters.
- Vector harness fails on unrecognized or silently-skipped cases.
- E2E suite includes negative-path authentication regressions.
- `zig build --help` shows focused test steps.
- README documents accurate install, compatibility, and contributor workflow.
- `.gitignore` removes generated Zig noise from normal status output.
- `zig build test` passes at the end of each merged workstream.

## Verification Matrix

- Fast correctness loop:
  - `zig test src/claims.zig`
  - `zig test src/pem.zig`
  - `zig test src/paserk/pbkw.zig`
- Workflow checks:
  - `zig build --help`
  - `zig build unit`
  - `zig build vectors`
  - `zig build e2e`
- Full regression:
  - `zig build test`

## Handoff Notes For The Next Agent

- Start with Task 1, not repo cleanup.
- Keep commits small and scoped to a single remediation theme.
- If a fix risks breaking official vectors, stop and inspect before widening the change.
- Do not “clean up” crypto code opportunistically during the hardening tasks.
- If you touch `README.md`, keep user-facing examples aligned with the exact public API in `src/root.zig`.
