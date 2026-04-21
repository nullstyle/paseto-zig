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

    const lid = try key.lid(allocator);
    defer allocator.free(lid);
    try std.testing.expect(std.mem.startsWith(u8, lid, "k4.lid."));

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
    const scalar = [_]u8{0x42} ** 48;
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
