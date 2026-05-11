# paseto-zig

A full-featured implementation of [PASETO](https://github.com/paseto-standard/paseto-spec)
(Platform-Agnostic Security Tokens) and [PASERK](https://github.com/paseto-standard/paserk)
(Platform-Agnostic Serialized Keys) for Zig `0.16.0+`.

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

Add `paseto-zig` to a consuming project's `build.zig.zon` with `zig fetch`.
Pin releases by tag, or pin unreleased builds by full commit SHA:

```sh
zig fetch --save-exact=paseto https://github.com/nullstyle/paseto-zig/archive/refs/tags/v0.1.0.tar.gz
zig fetch --save-exact=paseto https://github.com/nullstyle/paseto-zig/archive/<commit-sha>.tar.gz
```

That writes a dependency entry like this:

`build.zig.zon`:

```zig
.dependencies = .{
    .paseto = .{
        .url = "https://github.com/nullstyle/paseto-zig/archive/refs/tags/v0.1.0.tar.gz",
        .hash = "...",
    },
},
```

`build.zig`:

```zig
const paseto = b.dependency("paseto", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("paseto", paseto.module("paseto"));
```

To pin directly to a local checkout while developing, replace the `url`/`hash`
pair with a path relative to the consuming project's build root:

```zig
.dependencies = .{
    .paseto = .{
        .path = "../paseto-zig",
    },
},
```

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
// Identifiers as parsed handles.
const lid_id = try key.lid();       // paseto.paserk.Id { .version = .v4, .kind = .lid, ... }
const pid_id = try signer.pid();    // .kind = .pid
const sid_id = try signer.sid();    // .kind = .sid

// Canonical PASERK ID strings are still available when needed.
const lid = try lid_id.toString(allocator);  // "k4.lid.…"
defer allocator.free(lid);
const parsed_lid = try paseto.paserk.Id.parse(lid);
std.debug.assert(lid_id.eql(parsed_lid));

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

* **Zig:** `0.16.0` minimum in `build.zig.zon` and the default `mise.toml`
  toolchain. The standard tests and seed-only fuzz corpus are CI-gated on
  that stable release. Builtin mutation fuzzing with `--fuzz` still requires a
  revalidated development toolchain; it was last validated locally on
  `0.17.0-dev.256+04481c76c`. Do not float CI on `zig@master` without
  rerunning the full matrix, because nightly standard-library changes can
  break crypto tests independently of repo changes.
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

GitHub Actions runs the same core checks on an Ubuntu arm64 runner for pushes
to `main`, pull requests, and manual dispatches. To run that gate locally
without Docker, use the mise task:

```sh
mise run ci
```

To exercise the actual workflow locally, make sure Docker is running and use
the `act` task. The repo's `.actrc` pins the workflow file and maps
`ubuntu-24.04-arm` to an `act` runner image with the same `linux/arm64`
architecture as GitHub's hosted Ubuntu runner:

```sh
mise run act-ci-dry-run
mise run act-ci
```

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

The default mise/CI toolchain is Zig `0.16.0`, which covers the seed-only
fuzz corpus. For mutation-mode fuzzing, use a known-good development Zig
snapshot and re-run a bounded smoke command such as
`zig build fuzz-scenario --fuzz=1000` before starting a long soak.

Typical workflows:

* Start with a deterministic smoke run: `zig build fuzz-token`
* Stress one harness with mutations: `zig build fuzz-token --fuzz=1000`
* Sweep a whole class of harnesses: `zig build fuzz-parsers --fuzz`
* Exercise the envelope/API surface: `zig build fuzz-envelopes --fuzz`
* Run the scenario grammar interactively: `zig build fuzz-scenario --fuzz=10000 --webui`

### Long-run operator notes

Use one harness when you already know the bug family or want reproducible
iteration on a narrow input domain. Use a group step when you want broader
coverage across related harnesses without introducing new orchestration:
`fuzz-parsers` for decode/parse surfaces, `fuzz-envelopes` for PASERK and
high-level token APIs, and `fuzz-scenarios` when you want the deterministic
scenario smoke sweep across the bounded grammar families.

Mutation mode is opt-in. Add `--fuzz` for an open-ended builtin-fuzz session,
or `--fuzz=<limit>` when you want a bounded run that still starts from the
embedded seeds and regressions:

```sh
zig build fuzz-parsers --fuzz
zig build fuzz-envelopes --fuzz
zig build fuzz-scenario --fuzz=1000
```

Add `--webui` when you need interactive triage for a live mutation run. The
scenario harness is the best fit because it concentrates cross-module misuse
cases in one place without making every parser harness pay for UI overhead:

```sh
zig build fuzz-scenario --fuzz=10000 --webui
```

PBKW-heavy work should stay intentional instead of dominating every session.
The official vectors and the `fuzz-paserk_pbkw` harness both exercise Argon2
paths, so keep everyday iteration biased toward `zig build unit`,
`zig build e2e`, parser harnesses, or the non-PBKW envelope harnesses unless
you are actively touching PBKW code or password-wrapping invariants.

When a long run finds a crash, first reduce it to a stable repro with the
single harness target. Promote inputs that broaden future mutation coverage
into `tests/fuzz/corpus/<harness>/`, and promote fixed bug repros that must
never regress into `tests/fuzz/regressions/<harness>/`. After adding the new
input, wire it into the harness seed list with `@embedFile`, rerun the focused
harness, then rerun the relevant group step to confirm the seed-only sweep
still passes.

### Full-tilt Mac Studio recipe

For an operator-driven local soak on a machine that can spare the cores, run
the broad mutation passes separately so parser, envelope, and scenario work can
each accumulate coverage without extra orchestration code. In particular, do
not overlap scenario-mutating runs against the same corpus:

```sh
zig build fuzz-parsers --fuzz
zig build fuzz-envelopes --fuzz
zig build fuzz-scenario --fuzz --webui
```

Keep this local and on-demand. There is no CI, cron, or built-in coordinator
for these runs, and 48-hour soaks are manual, iterative sessions. This README
update was verified with bounded `--fuzz=<limit>` commands, not with an actual
48-hour soak. Long-run coverage is still bounded by the quality of the corpus
seeds and the invariants each harness encodes.

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

1. Install the repo tools with `mise install`, or install Zig `0.16.0`
   manually if you are not using mise.
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
