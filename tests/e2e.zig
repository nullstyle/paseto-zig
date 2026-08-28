//! End-to-end smoke tests exercising high-level key APIs, PASERK wrappers,
//! and the claims validator together.

const std = @import("std");
const paseto = @import("paseto");

test "PASERK Id works as a public hash map key" {
    const allocator = std.testing.allocator;
    const Map = std.HashMap(paseto.paserk.Id, u32, paseto.paserk.Id.HashContext, 80);

    const key_bytes: [32]u8 = @splat(0);
    const key = try paseto.v4.Local.fromBytes(&key_bytes);
    const computed = try key.lid();
    const encoded = try computed.toString(allocator);
    defer allocator.free(encoded);
    const parsed = try paseto.paserk.Id.parse(encoded);

    var map = Map.init(allocator);
    defer map.deinit();

    try map.put(computed, 10);
    try std.testing.expectEqual(@as(?u32, 10), map.get(parsed));

    var other_key_bytes: [32]u8 = @splat(0);
    other_key_bytes[0] = 1;
    const other_key = try paseto.v4.Local.fromBytes(&other_key_bytes);
    const different_digest = try other_key.lid();
    const different_kind = try paseto.paserk.id.pid(.v4, &key_bytes);
    const v3_key = try paseto.v3.Local.fromBytes(&key_bytes);
    const different_version = try v3_key.lid();

    try std.testing.expect(!computed.eql(different_digest));
    try std.testing.expect(!computed.eql(different_kind));
    try std.testing.expect(!computed.eql(different_version));

    try map.put(different_digest, 20);
    try map.put(different_kind, 30);
    try map.put(different_version, 40);

    try std.testing.expectEqual(@as(usize, 4), map.count());
    try std.testing.expectEqual(@as(?u32, 10), map.get(parsed));
    try std.testing.expectEqual(@as(?u32, 20), map.get(different_digest));
    try std.testing.expectEqual(@as(?u32, 30), map.get(different_kind));
    try std.testing.expectEqual(@as(?u32, 40), map.get(different_version));
}

test "v4.local encrypt/decrypt + lid + PIE round trip" {
    const allocator = std.testing.allocator;

    const key = paseto.v4.Local.generate();

    const tok = try key.encrypt(allocator, "{\"data\":\"top secret\"}", .{
        .footer = "{\"kid\":\"abc\"}",
        .implicit_assertion = "api:v1",
    });
    defer allocator.free(tok);

    const plaintext = try key.decrypt(allocator, tok, "api:v1");
    defer allocator.free(plaintext);
    try std.testing.expectEqualStrings("{\"data\":\"top secret\"}", plaintext);

    var decoded = try key.decryptWithFooter(allocator, tok, "api:v1");
    defer decoded.deinit();
    try std.testing.expectEqualStrings("{\"data\":\"top secret\"}", decoded.claims_bytes);
    try std.testing.expectEqualStrings("{\"kid\":\"abc\"}", decoded.footer);

    const local_paserk = try key.paserkLocal(allocator);
    defer allocator.free(local_paserk);
    const reparsed_key = try paseto.v4.Local.fromPaserk(allocator, local_paserk);
    try std.testing.expect(key.eql(reparsed_key));

    const lid_id = try key.lid();
    try std.testing.expect(lid_id.version == .v4);
    try std.testing.expect(lid_id.kind == .lid);

    const lid = try lid_id.toString(allocator);
    defer allocator.free(lid);
    try std.testing.expect(std.mem.startsWith(u8, lid, "k4.lid."));
    try std.testing.expect(lid_id.eql(try paseto.paserk.Id.parse(lid)));

    const other = paseto.v4.Local.generate();
    const wrapped = try key.wrapLocal(allocator, other, .{});
    defer allocator.free(wrapped);
    try std.testing.expect(std.mem.startsWith(u8, wrapped, "k4.local-wrap.pie."));

    var unwrapped = try key.unwrap(allocator, wrapped);
    defer unwrapped.deinit();
    try std.testing.expect(unwrapped.kind == .local);
    try std.testing.expectEqualSlices(u8, &other.key, unwrapped.bytes);
}

test "v4.public sign + seal + unseal" {
    const allocator = std.testing.allocator;

    const signer = paseto.v4.Public.generate();
    const local = paseto.v4.Local.generate();

    const sealed = try signer.seal(allocator, &local.key, null);
    defer allocator.free(sealed);
    try std.testing.expect(std.mem.startsWith(u8, sealed, "k4.seal."));

    const unsealed = try signer.unseal(allocator, sealed);
    defer allocator.free(unsealed);
    try std.testing.expectEqualSlices(u8, &local.key, unsealed);

    const tok = try signer.sign(allocator, "hello", .{});
    defer allocator.free(tok);
    const verified = try signer.verify(allocator, tok, "");
    defer allocator.free(verified);
    try std.testing.expectEqualStrings("hello", verified);

    const tok_with_footer = try signer.sign(allocator, "hello", .{ .footer = "kid:v4" });
    defer allocator.free(tok_with_footer);
    var verified_result = try signer.verifyWithFooter(allocator, tok_with_footer, "");
    defer verified_result.deinit();
    try std.testing.expectEqualStrings("hello", verified_result.claims_bytes);
    try std.testing.expectEqualStrings("kid:v4", verified_result.footer);

    const public_paserk = try signer.paserkPublic(allocator);
    defer allocator.free(public_paserk);
    const verifier = try paseto.v4.Public.fromPaserk(allocator, public_paserk);
    try std.testing.expect(!verifier.isPrivate());
    const secret_paserk = try signer.paserkSecret(allocator);
    defer allocator.free(secret_paserk);
    const signer_roundtrip = try paseto.v4.Public.fromPaserk(allocator, secret_paserk);
    try std.testing.expect(signer_roundtrip.isPrivate());
}

test "v3.local encrypt round trip + wrapSecret" {
    const allocator = std.testing.allocator;

    const key = paseto.v3.Local.generate();
    const tok = try key.encrypt(allocator, "{\"x\":1}", .{});
    defer allocator.free(tok);
    const plaintext = try key.decrypt(allocator, tok, "");
    defer allocator.free(plaintext);
    try std.testing.expectEqualStrings("{\"x\":1}", plaintext);

    const local_paserk = try key.paserkLocal(allocator);
    defer allocator.free(local_paserk);
    const reparsed_key = try paseto.v3.Local.fromPaserk(allocator, local_paserk);
    try std.testing.expect(key.eql(reparsed_key));

    // Wrap a fake 48-byte scalar (bytes don't need to be a valid P-384 scalar
    // for PIE to work, since it's just symmetric encryption).
    const scalar: [48]u8 = @splat(0x42);
    const wrapped = try key.wrapSecret(allocator, &scalar, .{});
    defer allocator.free(wrapped);
    var unwrapped = try key.unwrap(allocator, wrapped);
    defer unwrapped.deinit();
    try std.testing.expect(unwrapped.kind == .secret);
    try std.testing.expectEqualSlices(u8, &scalar, unwrapped.bytes);
}

test "v3.public PASERK and footer result round trip" {
    const allocator = std.testing.allocator;
    const signer = try paseto.v3.Public.generate();

    const tok = try signer.sign(allocator, "hello-v3", .{ .footer = "kid:v3" });
    defer allocator.free(tok);
    var verified = try signer.verifyWithFooter(allocator, tok, "");
    defer verified.deinit();
    try std.testing.expectEqualStrings("hello-v3", verified.claims_bytes);
    try std.testing.expectEqualStrings("kid:v3", verified.footer);

    const public_paserk = try signer.paserkPublic(allocator);
    defer allocator.free(public_paserk);
    const verifier = try paseto.v3.Public.fromPaserk(allocator, public_paserk);
    try std.testing.expect(!verifier.isPrivate());

    const secret_paserk = try signer.paserkSecret(allocator);
    defer allocator.free(secret_paserk);
    const signer_roundtrip = try paseto.v3.Public.fromPaserk(allocator, secret_paserk);
    try std.testing.expect(signer_roundtrip.isPrivate());
}

test "claims validator: exp/nbf/iat and custom audience" {
    const allocator = std.testing.allocator;

    const claims =
        \\{"exp":"2030-01-01T00:00:00Z","nbf":"2020-01-01T00:00:00Z",
        \\ "iat":"2020-01-01T00:00:00Z","aud":"svc.example.com","sub":"u","jti":"t1"}
    ;
    const v1: paseto.Validator = .{
        .now_override = 1_700_000_000,
        .expected_audience = &.{"svc.example.com"},
        .expected_subject = "u",
        .expected_token_identifier = "t1",
        .require_issuer = false,
    };
    try v1.validate(claims, allocator);

    const v2: paseto.Validator = .{
        .now_override = 1_700_000_000,
        .expected_audience = &.{"other.example.com"},
    };
    try std.testing.expectError(paseto.Error.InvalidAudience, v2.validate(claims, allocator));
}

test "v4.local rejects wrong implicit assertion" {
    const allocator = std.testing.allocator;
    const key = paseto.v4.Local.generate();
    const tok = try key.encrypt(allocator, "hello", .{ .implicit_assertion = "a" });
    defer allocator.free(tok);
    try std.testing.expectError(paseto.Error.InvalidAuthenticator, key.decrypt(allocator, tok, "b"));
}

test "v4.local rejects footer tampering" {
    const allocator = std.testing.allocator;
    const key = paseto.v4.Local.generate();
    const tok = try key.encrypt(allocator, "hello", .{ .footer = "footer-v1" });
    defer allocator.free(tok);

    var parsed = try paseto.token.parse(allocator, tok);
    defer parsed.deinit();
    parsed.footer[0] ^= 0x01;
    const tampered = try paseto.token.serialize(allocator, parsed.version, parsed.purpose, parsed.payload, parsed.footer);
    defer allocator.free(tampered);

    try std.testing.expectError(paseto.Error.InvalidAuthenticator, key.decrypt(allocator, tampered, ""));
}

test "v4.local rejects payload tampering" {
    const allocator = std.testing.allocator;
    const key = paseto.v4.Local.generate();
    const tok = try key.encrypt(allocator, "hello", .{});
    defer allocator.free(tok);

    var parsed = try paseto.token.parse(allocator, tok);
    defer parsed.deinit();
    // Flip a byte in the middle of the raw payload (which covers nonce,
    // ciphertext, and tag). Any position will cause MAC verification to
    // fail — the tag is the last 32 bytes so we flip there directly.
    parsed.payload[parsed.payload.len - 1] ^= 0x01;
    const tampered = try paseto.token.serialize(allocator, parsed.version, parsed.purpose, parsed.payload, parsed.footer);
    defer allocator.free(tampered);

    try std.testing.expectError(paseto.Error.InvalidAuthenticator, key.decrypt(allocator, tampered, ""));
}

test "v4.local rejects wrong key" {
    const allocator = std.testing.allocator;
    const signer = paseto.v4.Local.generate();
    const wrong = paseto.v4.Local.generate();
    const tok = try signer.encrypt(allocator, "hello", .{});
    defer allocator.free(tok);
    try std.testing.expectError(paseto.Error.InvalidAuthenticator, wrong.decrypt(allocator, tok, ""));
}

test "v4.public rejects signature tampering" {
    const allocator = std.testing.allocator;
    const seed: [32]u8 = @splat(0);
    const signer = try paseto.v4.Public.fromSeed(&seed);
    const tok = try signer.sign(allocator, "msg", .{});
    defer allocator.free(tok);

    // Parse the token, flip the last signature byte, re-emit with the same
    // serializer so the resulting base64 body is still well-formed.
    var parsed = try paseto.token.parse(allocator, tok);
    defer parsed.deinit();
    parsed.payload[parsed.payload.len - 1] ^= 0x01;
    const tampered = try paseto.token.serialize(allocator, parsed.version, parsed.purpose, parsed.payload, parsed.footer);
    defer allocator.free(tampered);

    try std.testing.expectError(paseto.Error.InvalidSignature, signer.verify(allocator, tampered, ""));
}

test "v4.public rejects verification with wrong key" {
    const allocator = std.testing.allocator;
    const signer = paseto.v4.Public.generate();
    const other = paseto.v4.Public.generate();
    const tok = try signer.sign(allocator, "msg", .{});
    defer allocator.free(tok);
    try std.testing.expectError(paseto.Error.InvalidSignature, other.verify(allocator, tok, ""));
}

test "Token parser rejects malformed inputs" {
    const allocator = std.testing.allocator;
    const key = paseto.v4.Local.generate();
    // Missing third segment.
    try std.testing.expectError(paseto.Error.InvalidToken, key.decrypt(allocator, "v4.local", ""));
    // Unknown version.
    try std.testing.expectError(paseto.Error.UnsupportedVersion, key.decrypt(allocator, "v2.local.AAAA", ""));
    // Unknown purpose.
    try std.testing.expectError(paseto.Error.UnsupportedPurpose, key.decrypt(allocator, "v4.nope.AAAA", ""));
    // Padded base64 (PASETO forbids).
    try std.testing.expectError(paseto.Error.InvalidPadding, key.decrypt(allocator, "v4.local.AAA=", ""));
}

test "claims validator rejects malformed required claims" {
    const allocator = std.testing.allocator;
    const validator: paseto.Validator = .{
        .require_issuer = true,
        .now_override = 1_700_000_000,
    };
    try std.testing.expectError(paseto.Error.InvalidIssuer, validator.validate("{\"iss\":1}", allocator));
}

test "claims validator rejects missing expected claims" {
    const allocator = std.testing.allocator;
    const validator: paseto.Validator = .{
        .expected_issuer = "auth.example.com",
        .expected_audience = &.{"svc.example.com"},
        .now_override = 1_700_000_000,
    };
    try std.testing.expectError(
        paseto.Error.InvalidIssuer,
        validator.validate("{\"aud\":\"svc.example.com\"}", allocator),
    );
    try std.testing.expectError(
        paseto.Error.InvalidAudience,
        validator.validate("{\"iss\":\"auth.example.com\"}", allocator),
    );
}

test "key round trip via PEM (v4.public seed)" {
    const allocator = std.testing.allocator;
    const pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0
        \\-----END PRIVATE KEY-----
    ;
    var parsed = try paseto.pem.parse(allocator, pem);
    defer parsed.deinit();
    try std.testing.expect(parsed.format == .ed25519_seed);

    const signer = try paseto.v4.Public.fromSeed(parsed.bytes);
    const tok = try signer.sign(allocator, "abc", .{});
    defer allocator.free(tok);

    const verifier = try paseto.v4.Public.fromPublicKeyBytes(&signer.publicKeyBytes());
    const check = try verifier.verify(allocator, tok, "");
    defer allocator.free(check);
    try std.testing.expectEqualStrings("abc", check);
}

// ----- v3 tamper coverage (v4 equivalents above) --------------------------

test "v3.local rejects wrong implicit assertion" {
    const allocator = std.testing.allocator;
    const key = paseto.v3.Local.generate();
    const tok = try key.encrypt(allocator, "hello", .{ .implicit_assertion = "a" });
    defer allocator.free(tok);
    try std.testing.expectError(paseto.Error.InvalidAuthenticator, key.decrypt(allocator, tok, "b"));
}

test "v3.local rejects footer tampering" {
    const allocator = std.testing.allocator;
    const key = paseto.v3.Local.generate();
    const tok = try key.encrypt(allocator, "hello", .{ .footer = "footer-v3" });
    defer allocator.free(tok);

    var parsed = try paseto.token.parse(allocator, tok);
    defer parsed.deinit();
    parsed.footer[0] ^= 0x01;
    const tampered = try paseto.token.serialize(allocator, parsed.version, parsed.purpose, parsed.payload, parsed.footer);
    defer allocator.free(tampered);

    try std.testing.expectError(paseto.Error.InvalidAuthenticator, key.decrypt(allocator, tampered, ""));
}

test "v3.public rejects wrong implicit assertion" {
    const allocator = std.testing.allocator;
    const signer = try paseto.v3.Public.generate();
    const tok = try signer.sign(allocator, "hello", .{ .implicit_assertion = "a" });
    defer allocator.free(tok);
    try std.testing.expectError(paseto.Error.InvalidSignature, signer.verify(allocator, tok, "b"));
}

test "v3.public rejects signature tampering" {
    const allocator = std.testing.allocator;
    const signer = try paseto.v3.Public.generate();
    const tok = try signer.sign(allocator, "msg", .{});
    defer allocator.free(tok);

    var parsed = try paseto.token.parse(allocator, tok);
    defer parsed.deinit();
    parsed.payload[parsed.payload.len - 1] ^= 0x01;
    const tampered = try paseto.token.serialize(allocator, parsed.version, parsed.purpose, parsed.payload, parsed.footer);
    defer allocator.free(tampered);

    try std.testing.expectError(paseto.Error.InvalidSignature, signer.verify(allocator, tampered, ""));
}

// ----- parser size-cap boundaries ------------------------------------------

test "token parser enforces the 1 MiB cap at the boundary" {
    const allocator = std.testing.allocator;

    // Build a structurally valid token whose total length is exactly the
    // cap: header + base64url payload + '.' + base64url footer filler. The
    // footer filler length is fixed by the cap, so pick a payload size whose
    // encoding leaves a decodable footer length (mod 4 != 1).
    const candidates = [_]usize{ 65, 66, 67 };
    var chosen: ?[]u8 = null;
    defer if (chosen) |c| allocator.free(c);
    for (candidates) |payload_len| {
        const payload = try allocator.alloc(u8, payload_len);
        defer allocator.free(payload);
        @memset(payload, 0x41);
        const pb64 = try paseto.util.encodeBase64Alloc(allocator, payload);
        defer allocator.free(pb64);
        const footer_len = paseto.util.max_token_string_bytes - "v4.local.".len - pb64.len - 1;
        if (footer_len % 4 == 1) continue;

        const at_cap = try allocator.alloc(u8, paseto.util.max_token_string_bytes);
        @memcpy(at_cap[0.."v4.local.".len], "v4.local.");
        @memcpy(at_cap["v4.local.".len .. "v4.local.".len + pb64.len], pb64);
        at_cap["v4.local.".len + pb64.len] = '.';
        @memset(at_cap["v4.local.".len + pb64.len + 1 ..], 'A');
        chosen = at_cap;
        break;
    }
    const at_cap = chosen orelse return error.NoValidPayloadSize;

    {
        var parsed = try paseto.token.parse(allocator, at_cap);
        defer parsed.deinit();
        try std.testing.expect(parsed.version == .v4);
        try std.testing.expect(parsed.purpose == .local);
    }

    const over_cap = try allocator.alloc(u8, at_cap.len + 1);
    defer allocator.free(over_cap);
    @memcpy(over_cap[0..at_cap.len], at_cap);
    over_cap[over_cap.len - 1] = 'A';
    try std.testing.expectError(paseto.Error.InvalidToken, paseto.token.parse(allocator, over_cap));
}

test "paserk parser enforces the 4096-byte cap at the boundary" {
    const allocator = std.testing.allocator;
    const cap = paseto.util.max_paserk_string_bytes;

    const at_cap = try allocator.alloc(u8, cap);
    defer allocator.free(at_cap);
    @memcpy(at_cap[0.."k4.local.".len], "k4.local.");
    @memset(at_cap["k4.local.".len..], 'A');
    // At the cap the parser proceeds past the size check and rejects the
    // (wrong-length) key body instead.
    try std.testing.expectError(paseto.Error.InvalidKey, paseto.paserk.keys.parse(allocator, at_cap));

    const over_cap = try allocator.alloc(u8, cap + 1);
    defer allocator.free(over_cap);
    @memcpy(over_cap[0..at_cap.len], at_cap);
    over_cap[over_cap.len - 1] = 'A';
    try std.testing.expectError(paseto.Error.InvalidEncoding, paseto.paserk.keys.parse(allocator, over_cap));
}

test "Claims.init enforces the 64 KiB cap at the boundary" {
    const allocator = std.testing.allocator;
    const cap = paseto.util.max_claims_json_bytes;

    const json = try allocator.alloc(u8, cap);
    defer allocator.free(json);
    @memcpy(json[0..6], "{\"a\":\"");
    @memset(json[5 .. cap - 2], 'x');
    @memcpy(json[cap - 2 ..], "\"}");
    {
        var claims = try paseto.Claims.init(allocator, json);
        defer claims.deinit();
    }

    const over = try allocator.alloc(u8, cap + 1);
    defer allocator.free(over);
    @memcpy(over[0..json.len], json);
    over[over.len - 1] = ' ';
    try std.testing.expectError(paseto.Error.InvalidClaim, paseto.Claims.init(allocator, over));
}

test "pem parser enforces the 64 KiB cap" {
    const allocator = std.testing.allocator;
    const big = try allocator.alloc(u8, paseto.util.max_pem_bytes + 1);
    defer allocator.free(big);
    @memcpy(big[0.."-----BEGIN PRIVATE KEY-----".len], "-----BEGIN PRIVATE KEY-----");
    @memset(big["-----BEGIN PRIVATE KEY-----".len .. big.len - "-END-----".len], 'A');
    @memcpy(big[big.len - "-----END PRIVATE KEY-----".len ..], "-----END PRIVATE KEY-----");
    try std.testing.expectError(paseto.Error.InvalidEncoding, paseto.pem.parse(allocator, big));
}

// ----- PBKW negatives -------------------------------------------------------

test "PBKW unwrap rejects wrong password and tampered tag" {
    const allocator = std.testing.allocator;
    const key = paseto.v4.Local.generate();

    // Testing-policy Argon2id params keep the e2e suite fast (std requires
    // at least 8 KiB); the wrap/unwrap logic under test is policy-independent.
    const wrapped = try key.wrapWithPassword(allocator, "correct horse", .{
        .params = .{ .memlimit_bytes = 16 * 1024, .opslimit = 1 },
        .policy = .testing,
    });
    defer allocator.free(wrapped);
    try std.testing.expect(std.mem.startsWith(u8, wrapped, "k4.local-pw."));

    // Wrong password derives a different Ke/Ki and must fail the tag.
    try std.testing.expectError(
        paseto.Error.InvalidAuthenticator,
        paseto.paserk.pbkw.unwrapWithPolicy(allocator, "wrong horse", wrapped, .testing),
    );

    // Corrupt the final body byte (inside the MAC/tag region) while keeping
    // the base64 alphabet valid.
    const tampered = try allocator.dupe(u8, wrapped);
    defer allocator.free(tampered);
    const last = tampered[tampered.len - 1];
    tampered[tampered.len - 1] = if (last == 'A') 'B' else 'A';
    try std.testing.expectError(
        paseto.Error.InvalidAuthenticator,
        paseto.paserk.pbkw.unwrapWithPolicy(allocator, "correct horse", tampered, .testing),
    );
}

// ----- PIE / PKE header-confusion negatives ---------------------------------

test "PIE unwrap rejects cross-kind header confusion" {
    const allocator = std.testing.allocator;
    const wrapping = paseto.v4.Local.generate();
    const victim = paseto.v4.Local.generate();

    const wrapped = try wrapping.wrapLocal(allocator, victim, .{});
    defer allocator.free(wrapped);

    // v4 secret-wrap and local-wrap wrap differently sized key material
    // (Ed25519 seeds carry extra framing), so the exact-length check must
    // fire before any decoding or MAC work.
    const body = wrapped["k4.local-wrap.pie.".len..];
    const confused = try std.mem.concat(allocator, u8, &.{ "k4.secret-wrap.pie.", body });
    defer allocator.free(confused);
    try std.testing.expectError(paseto.Error.InvalidEncoding, wrapping.unwrap(allocator, confused));
}

test "PIE unwrap rejects cross-version header confusion" {
    const allocator = std.testing.allocator;
    const wrapping = paseto.v4.Local.generate();
    const victim = paseto.v4.Local.generate();

    const wrapped = try wrapping.wrapLocal(allocator, victim, .{});
    defer allocator.free(wrapped);

    // v3 PIE bodies (48-byte tag) have a different length than v4 (32-byte
    // tag), so the length check must fire before any decoding.
    const body = wrapped["k4.local-wrap.pie.".len..];
    const confused = try std.mem.concat(allocator, u8, &.{ "k3.local-wrap.pie.", body });
    defer allocator.free(confused);
    try std.testing.expectError(paseto.Error.InvalidEncoding, wrapping.unwrap(allocator, confused));
}

test "PKE unseal rejects cross-version header confusion" {
    const allocator = std.testing.allocator;
    const recipient = paseto.v4.Public.generate();
    const secret: [32]u8 = @splat(0x5a);

    const sealed = try recipient.seal(allocator, &secret, null);
    defer allocator.free(sealed);

    const body = sealed["k4.seal.".len..];
    const confused = try std.mem.concat(allocator, u8, &.{ "k3.seal.", body });
    defer allocator.free(confused);
    try std.testing.expectError(paseto.Error.InvalidEncoding, recipient.unseal(allocator, confused));
}
