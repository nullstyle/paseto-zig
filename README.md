# paseto-zig

A full-featured implementation of [PASETO](https://github.com/paseto-standard/paseto-spec)
(Platform-Agnostic Security Tokens) and [PASERK](https://github.com/paseto-standard/paserk)
(Platform-Agnostic Serialized Keys) for Zig `0.16.0-dev`.

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

Add this repo as a dependency to your `build.zig.zon`:

```zig
.dependencies = .{
    .paseto = .{ .url = "…", .hash = "…" },
},
```

Then in your `build.zig`:

```zig
const paseto = b.dependency("paseto", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("paseto", paseto.module("paseto"));
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

* **Zig:** `0.16.0-dev` (uses the new `std.Io` interface).
* **Randomness:** library functions that need entropy (key / nonce / salt
  generation) draw from `std.Io.Threaded.global_single_threaded`, which is
  backed by the host operating system's CSPRNG. Callers who need their own
  `Io` can use the lower-level byte APIs and inject deterministic
  `nonce` / `salt` / `ephemeral_override` values (used by the vector tests).

## Testing

```sh
zig build test
```

The test suite runs three passes:

1. Unit tests embedded in each source file (crypto round trips, utility
   sanity checks, PEM decode for each supported key format).
2. `tests/vectors.zig` — every official PASETO/PASERK test vector shipped
   under `tests/vectors/*.json`.
3. `tests/e2e.zig` — end-to-end examples exercising the high-level API.

The PBKW argon2id tests dominate runtime (≈30 s on a typical machine); set
lower limits in `opts.params` if you need faster turnaround when
prototyping.

## Acknowledgements

This port's feature scope and test surface mirror the Ruby
[ruby-paseto](https://github.com/bannable/paseto) library, which is vendored
under `vendor/ruby/` for reference. See that project's README for protocol
discussion, security considerations, and history.

## License

MIT — see `LICENSE.txt`.
