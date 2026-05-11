//! End-to-end smoke tests exercising high-level key APIs, PASERK wrappers,
//! and the claims validator together.

const std = @import("std");
const paseto = @import("paseto");

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
}

test "v3.local encrypt round trip + wrapSecret" {
    const allocator = std.testing.allocator;

    const key = paseto.v3.Local.generate();
    const tok = try key.encrypt(allocator, "{\"x\":1}", .{});
    defer allocator.free(tok);
    const plaintext = try key.decrypt(allocator, tok, "");
    defer allocator.free(plaintext);
    try std.testing.expectEqualStrings("{\"x\":1}", plaintext);

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
