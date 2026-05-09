# paseto-zig

A full-featured implementation of [PASETO](https://github.com/paseto-standard/paseto-spec)
(Platform-Agnostic Security Tokens) and [PASERK](https://github.com/paseto-standard/paserk)
(Platform-Agnostic Serialized Keys) for Zig `0.17.0-dev.256+04481c76c`.

Supports PASETO `v3` (NIST Modern — AES-256-CTR, HMAC-SHA384, ECDSA P-384)
and `v4` (Sodium Modern — XChaCha20, BLAKE2b-keyed, Ed25519), covering both
`local` (symmetric) and `public` (asymmetric) purposes, plus every registered
PASERK operation:

|                  | v3 | v4 |
| ---------------- | -- | -- |
| `local`          | ✅ | ✅ |
| `public`         | ✅ | ✅ |
| `secret`         | ✅ | ✅ |
| `lid` / `sid` / `pid` | ✅ | ✅ |
| `local-wrap.pie` / `secret-wrap.pie` | ✅ | ✅ |
| `seal`           | ✅ | ✅ |
| `local-pw` / `secret-pw` | ✅ | ✅ |

The library passes the [official PASETO and PASERK test vectors](https://github.com/paseto-standard/test-vectors)
for every supported protocol and PASERK type.

## Installing

> **Note:** The library is not yet published to a public registry. For now
> add it as a local or git dependency. Once `paseto-zig` is published the
> URL+hash values below will become real.

`build.zig.zon`:

```zig
.dependencies = .{
    .paseto = .{
        // TODO: populate once paseto-zig has a published release.
        .url = "https://example.invalid/paseto-zig-0.1.0.tar.gz",
        .hash = "0000000000000000000000000000000000000000000000000000000000000000",
    },
},
```

`build.zig`:

```zig
const paseto = b.dependency("paseto", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("paseto", paseto.module("paseto"));
```

To pin directly to a local checkout while developing, replace the `url`/`hash`
pair with `.path = "/abs/path/to/paseto-zig"`.

## Quick tour

### v4.local (XChaCha20 + BLAKE2b)

```zig
const paseto = @import("paseto");

const key = paseto.v4.Local.generate();
const token = try key.encrypt(allocator, "{\"sub\":\"alice\"}", .{
    .footer = "{\"kid\":\"abc\"}",
    .implicit_assertion = "api:v1",
});
defer allocator.free(token);

const plaintext = try key.decrypt(allocator, token, "api:v1");
defer allocator.free(plaintext);
```

### v4.public (Ed25519)

```zig
const signer = paseto.v4.Public.generate();
const token = try signer.sign(allocator, "hello", .{});
defer allocator.free(token);

const verifier = try paseto.v4.Public.fromPublicKeyBytes(&signer.publicKeyBytes());
const verified = try verifier.verify(allocator, token, "");
defer allocator.free(verified);
```

### v3.local and v3.public

```zig
const k3 = paseto.v3.Local.generate();
const token = try k3.encrypt(allocator, "{\"x\":1}", .{});
defer allocator.free(token);

const p3 = try paseto.v3.Public.generate();
const sig_token = try p3.sign(allocator, "hello", .{});
defer allocator.free(sig_token);
```

### PEM / DER key import

```zig
const pem_text =
    \\-----BEGIN EC PRIVATE KEY-----
    \\...
    \\-----END EC PRIVATE KEY-----
;
var parsed = try paseto.pem.parse(allocator, pem_text);
defer parsed.deinit();
const signer = try paseto.v3.Public.fromScalarBytes(parsed.bytes);
```

`pem.parse` recognises:

* `-----BEGIN EC PRIVATE KEY-----` (SEC1 ECPrivateKey for P-384 → 48-byte scalar)
* `-----BEGIN PRIVATE KEY-----` (PKCS#8; Ed25519 → 32-byte seed, P-384 → 48-byte scalar)
* `-----BEGIN PUBLIC KEY-----` (SubjectPublicKeyInfo; Ed25519 or P-384)

### PASERK

Every PASERK operation is exposed both on the high-level key types and via
byte-level helpers in `paseto.paserk`.

```zig
// Identifiers.
const lid = try key.lid(allocator);      // "k4.lid.…"
const pid = try signer.pid(allocator);   // "k4.pid.…"
const sid = try signer.sid(allocator);   // "k4.sid.…"

// PIE wrap (symmetric key wrap).
const wrapped = try key.wrapLocal(allocator, other_key, .{});  // "k4.local-wrap.pie.…"
var unwrapped = try key.unwrap(allocator, wrapped);
defer unwrapped.deinit();

// PKE (public-key encryption / sealing).
const sealed = try signer.seal(allocator, &other_key.key, null);  // "k4.seal.…"
const unsealed = try signer.unseal(allocator, sealed);
defer allocator.free(unsealed);

// PBKW (password-based wrapping).
const wrapped_pw = try key.wrapWithPassword(allocator, "correct horse…", .{
    .params = .{ .memlimit_bytes = 64 * 1024 * 1024, .opslimit = 2 },
});
defer allocator.free(wrapped_pw);

var unwrapped_pw = try paseto.paserk.pbkw.unwrap(allocator, "correct horse…", wrapped_pw);
defer unwrapped_pw.deinit();
```

### Registered claims validation

```zig
const validator: paseto.Validator = .{
    .verify_exp = true,
    .verify_nbf = true,
    .verify_iat = true,
    .expected_issuer = "auth.example.com",
    .expected_audience = &.{"svc.example.com"},
};

// `claims_json` is the plaintext you got back from `decrypt` / `verify`.
try validator.validate(claims_json, allocator);
```

The validator understands the six PASETO registered claims (`exp`, `nbf`,
`iat`, `iss`, `aud`, `sub`, `jti`). Timestamps are parsed from ISO-8601
strings in the form `YYYY-MM-DDTHH:MM:SS(.fff)?(Z|±HH:MM)`.

## Compatibility

* **Zig:** `0.17.0-dev.256+04481c76c` (the version currently validated for the
  full test and builtin-fuzz workflow in this repository). Earlier versions
  are not supported.
* **Randomness:** library functions that need entropy (key / nonce / salt
  generation) draw from `std.Io.Threaded.global_single_threaded`, which is
  backed by the host operating system's CSPRNG. Callers who need their own
  `Io` can use the lower-level byte APIs and inject deterministic
  `nonce` / `salt` / `ephemeral_override` values (used by the vector tests).

## Testing

```sh
# Full suite (unit + vectors + e2e).
zig build test

# Focused entrypoints — see `zig build --help` for the full list.
zig build unit     # source-embedded unit tests only (fast, <1s)
zig build vectors  # official PASETO/PASERK test vectors (≈30s — argon2id)
zig build e2e      # end-to-end smoke tests using the public API
```

The PBKW argon2id vectors dominate wall-clock runtime; when iterating on
unrelated changes use `zig build unit` or `zig build e2e` for fast feedback
and only run `zig build test` before committing.

## Fuzzing

Thirteen harnesses plus a cross-module scenario harness live under
`tests/fuzz/`, covering the parser surface (token, util codecs, claims,
PEM/DER, PASERK keys), the envelope surface (PIE, PKE, PBKW, PASERK IDs,
all four high-level `v3/v4.Local`/`.Public` APIs), and a bounded scenario
grammar with ten families (round-trip, mutation-reject, mixed-version and
mixed-purpose misuse).

Group steps:

```sh
zig build fuzz-all             # full suite, seed-only by default
zig build fuzz-parsers --fuzz  # parser harnesses with mutation enabled
zig build fuzz-envelopes --fuzz
zig build fuzz-scenarios       # scenario grammar harness, seed-only by default
```

Focused runs and repros:

```sh
zig build fuzz-token --fuzz=1000
zig build fuzz-scenario --fuzz=10000 --webui
```

Per-harness targets for focused repro after a crash:

```sh
zig build fuzz-token
zig build fuzz-util
zig build fuzz-claims
zig build fuzz-pem
zig build fuzz-paserk_keys
zig build fuzz-paserk_pie
zig build fuzz-paserk_pke
zig build fuzz-paserk_pbkw
zig build fuzz-paserk_id
zig build fuzz-v4_local
zig build fuzz-v4_public
zig build fuzz-v3_local
zig build fuzz-v3_public
zig build fuzz-scenario
```

Plain `zig build fuzz-...` runs a deterministic seed-only smoke pass: the
harness test artifact executes once against its embedded corpus seeds and any
wired regression inputs. Add `--fuzz[=limit]` to enable Zig's builtin mutation
engine on top of that seeded startup. `--webui` is available with builtin fuzz
mode and is especially useful for long-running scenario triage.

Typical workflows:

* Start with a deterministic smoke run: `zig build fuzz-token`
* Stress one harness with mutations: `zig build fuzz-token --fuzz=1000`
* Sweep a whole class of harnesses: `zig build fuzz-parsers --fuzz`
* Exercise the envelope/API surface: `zig build fuzz-envelopes --fuzz`
* Run the scenario grammar interactively: `zig build fuzz-scenario --fuzz=10000 --webui`

### Corpus and regression policy

* Seed corpora live at `tests/fuzz/corpus/<harness>/*.bin`. Keep hand-curated
  seeds small (~3–10 files per harness); each fuzz run starts from these
  embedded corpus inputs before mutating.
* Any reproducible crash found during a long run becomes either a permanent
  corpus seed under `tests/fuzz/corpus/<harness>/` or a deterministic
  regression input under `tests/fuzz/regressions/<harness>/`, then wired
  into the harness's seed list via `@embedFile`.
* Each harness's allowed-error set is locked by the spec's rejection
  contract. An error outside that set is a bug, not a license to broaden
  the set.
* PBKW harnesses use bounded Argon2 parameters from
  `tests/fuzz/support.zig` (`PbkwV4FuzzParams` / `PbkwV3FuzzParams`) so
  iterations stay cheap. Do not fuzz `memlimit_bytes` or `opslimit`
  directly except through the explicit `WeakParameters` negative test.

## Contributing

1. Install Zig `0.17.0-dev.256+04481c76c`.
2. Clone with submodules if you want the Ruby reference (optional):
   ```sh
   git clone --recurse-submodules …
   ```
   The `vendor/ruby/` tree is **reference only**. Do not edit it as part of
   normal changes to the Zig library; it exists so reviewers can diff
   against the upstream Ruby implementation's feature set.
3. Make your change. Prefer narrowly-scoped commits with their own tests.
4. Run `zig build test` and ensure the full suite is green before pushing.
5. If your change touches parser / envelope / high-level code that already
   has a fuzz harness, also run `zig build fuzz-all` for the deterministic
   seed-only sweep before pushing. Add `--fuzz[=limit]` and `--webui` when
   you want mutation mode or interactive triage.

## Acknowledgements

This port's feature scope and test surface mirror the Ruby
[ruby-paseto](https://github.com/bannable/paseto) library, which is vendored
under `vendor/ruby/` for reference. See that project's README for protocol
discussion, security considerations, and history.

## License

MIT — see `LICENSE.txt`.
