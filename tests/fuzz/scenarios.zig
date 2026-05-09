//! Cross-module scenario fuzz harness. Ten scenario families, each bounded
//! to the exact operation sequence described in the design doc.
//!
//! Round-trip families assert success-only outcomes — any error is a bug.
//! Mutation-reject and misuse families allow a tightly-scoped error set per
//! the spec's rejection contract.

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds = [_][]const u8{
    // seed_01.bin -> local_round_trip
    @embedFile("corpus/scenarios/seed_01.bin"),
    // seed_02.bin -> public_round_trip
    @embedFile("corpus/scenarios/seed_02.bin"),
    // seed_03.bin -> local_mutation_reject
    @embedFile("corpus/scenarios/seed_03.bin"),
    // seed_04.bin -> public_mutation_reject
    @embedFile("corpus/scenarios/seed_04.bin"),
    // seed_05.bin -> paserk_key_round_trip
    @embedFile("corpus/scenarios/seed_05.bin"),
    // seed_06.bin -> pie_round_trip
    @embedFile("corpus/scenarios/seed_06.bin"),
    // seed_07.bin -> pke_round_trip
    @embedFile("corpus/scenarios/seed_07.bin"),
    // seed_08.bin -> pbkw_round_trip
    @embedFile("corpus/scenarios/seed_08.bin"),
    // seed_09.bin -> mixed_version_misuse
    @embedFile("corpus/scenarios/seed_09.bin"),
    // seed_10.bin -> mixed_purpose_misuse
    @embedFile("corpus/scenarios/seed_10.bin"),
};

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
    mutated_authenticator_signature,
    malformed_framing,
};

const malformed_token_errors = [_]paseto.Error{error.InvalidToken};
const misuse_errors = [_]paseto.Error{error.WrongPurpose};

test "fuzz: scenario grammar" {
    try std.testing.fuzz({}, dispatch, .{ .corpus = &seeds });
}

fn dispatch(_: void, s: *std.testing.Smith) anyerror!void {
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

fn runLocalRoundTrip(s: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    const version = s.value(paseto.Version);
    var key_buf: [32]u8 = undefined;
    s.bytes(&key_buf);
    var msg_buf: [256]u8 = undefined;
    const msg = msg_buf[0..s.slice(&msg_buf)];
    var footer_buf: [64]u8 = undefined;
    const footer = footer_buf[0..s.slice(&footer_buf)];
    var assertion_buf: [64]u8 = undefined;
    const assertion = assertion_buf[0..s.slice(&assertion_buf)];
    var nonce: [32]u8 = undefined;
    s.bytes(&nonce);

    switch (version) {
        .v3 => {
            const key = try paseto.v3.Local.fromBytes(&key_buf);
            const tok = try key.encrypt(allocator, msg, .{
                .footer = footer,
                .implicit_assertion = assertion,
                .nonce = nonce,
            });
            defer allocator.free(tok);
            const out = try key.decrypt(allocator, tok, assertion);
            defer allocator.free(out);
            try std.testing.expectEqualSlices(u8, msg, out);
        },
        .v4 => {
            const key = try paseto.v4.Local.fromBytes(&key_buf);
            const tok = try key.encrypt(allocator, msg, .{
                .footer = footer,
                .implicit_assertion = assertion,
                .nonce = nonce,
            });
            defer allocator.free(tok);
            const out = try key.decrypt(allocator, tok, assertion);
            defer allocator.free(out);
            try std.testing.expectEqualSlices(u8, msg, out);
        },
    }
}

fn runPublicRoundTrip(s: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    const version = s.value(paseto.Version);
    var msg_buf: [256]u8 = undefined;
    const msg = msg_buf[0..s.slice(&msg_buf)];
    var footer_buf: [64]u8 = undefined;
    const footer = footer_buf[0..s.slice(&footer_buf)];
    var assertion_buf: [64]u8 = undefined;
    const assertion = assertion_buf[0..s.slice(&assertion_buf)];

    switch (version) {
        .v3 => {
            var scalar: [48]u8 = undefined;
            s.bytes(&scalar);
            const pk = try support.deriveValidV3Public(scalar);
            const signed = try pk.sign(allocator, msg, .{ .footer = footer, .implicit_assertion = assertion });
            defer allocator.free(signed);
            const recovered = try pk.verify(allocator, signed, assertion);
            defer allocator.free(recovered);
            try std.testing.expectEqualSlices(u8, msg, recovered);
        },
        .v4 => {
            var seed: [32]u8 = undefined;
            s.bytes(&seed);
            const pk = try paseto.v4.Public.fromSeed(&seed);
            const signed = try pk.sign(allocator, msg, .{ .footer = footer, .implicit_assertion = assertion });
            defer allocator.free(signed);
            const recovered = try pk.verify(allocator, signed, assertion);
            defer allocator.free(recovered);
            try std.testing.expectEqualSlices(u8, msg, recovered);
        },
    }
}

fn runLocalMutationReject(s: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    const version = s.value(paseto.Version);
    const mismatch = s.value(MismatchClass);
    var key_buf: [32]u8 = undefined;
    s.bytes(&key_buf);
    var msg_buf: [128]u8 = undefined;
    const msg = msg_buf[0..s.slice(&msg_buf)];
    var footer_buf: [32]u8 = undefined;
    const footer = footer_buf[0..s.slice(&footer_buf)];
    var assertion_buf: [32]u8 = undefined;
    const assertion = assertion_buf[0..s.slice(&assertion_buf)];
    var nonce: [32]u8 = undefined;
    s.bytes(&nonce);

    switch (version) {
        .v3 => {
            const key = try paseto.v3.Local.fromBytes(&key_buf);
            const tok = try key.encrypt(allocator, msg, .{
                .footer = footer,
                .implicit_assertion = assertion,
                .nonce = nonce,
            });
            defer allocator.free(tok);
            try exerciseLocalMismatchV3(allocator, s, key_buf, assertion, tok, mismatch);
        },
        .v4 => {
            const key = try paseto.v4.Local.fromBytes(&key_buf);
            const tok = try key.encrypt(allocator, msg, .{
                .footer = footer,
                .implicit_assertion = assertion,
                .nonce = nonce,
            });
            defer allocator.free(tok);
            try exerciseLocalMismatchV4(allocator, s, key_buf, assertion, tok, mismatch);
        },
    }
}

fn runPublicMutationReject(s: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    const version = s.value(paseto.Version);
    const mismatch = s.value(MismatchClass);
    var msg_buf: [128]u8 = undefined;
    const msg_len = s.slice(&msg_buf);
    if (mismatch == .mutated_payload and msg_len == 0) {
        // Public tokens with empty messages have no payload bytes outside the
        // signature/authenticator, so forcing one content byte keeps this
        // mismatch class from degenerating into a no-op mutation.
        msg_buf[0] = 0;
    }
    const msg = if (mismatch == .mutated_payload and msg_len == 0)
        msg_buf[0..1]
    else
        msg_buf[0..msg_len];
    var footer_buf: [32]u8 = undefined;
    const footer = footer_buf[0..s.slice(&footer_buf)];
    var assertion_buf: [32]u8 = undefined;
    const assertion = assertion_buf[0..s.slice(&assertion_buf)];

    switch (version) {
        .v3 => {
            var scalar: [48]u8 = undefined;
            s.bytes(&scalar);
            const pk = try support.deriveValidV3Public(scalar);
            const tok = try pk.sign(allocator, msg, .{
                .footer = footer,
                .implicit_assertion = assertion,
            });
            defer allocator.free(tok);
            try exercisePublicMismatchV3(allocator, s, scalar, assertion, tok, mismatch);
        },
        .v4 => {
            var seed: [32]u8 = undefined;
            s.bytes(&seed);
            const pk = try paseto.v4.Public.fromSeed(&seed);
            const tok = try pk.sign(allocator, msg, .{
                .footer = footer,
                .implicit_assertion = assertion,
            });
            defer allocator.free(tok);
            try exercisePublicMismatchV4(allocator, s, seed, assertion, tok, mismatch);
        },
    }
}

fn runPaserkKeyRoundTrip(s: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    const version = s.value(paseto.Version);
    const kind = s.value(paseto.paserk.KeyType);
    const len: usize = switch (version) {
        .v3 => switch (kind) {
            .local => 32,
            .public => 49,
            .secret => 48,
        },
        .v4 => switch (kind) {
            .local => 32,
            .public => 32,
            .secret => 64,
        },
    };
    var buf: [64]u8 = undefined;
    s.bytes(buf[0..len]);

    const paserk_str = try paseto.paserk.keys.serialize(allocator, version, kind, buf[0..len]);
    defer allocator.free(paserk_str);
    var decoded = try paseto.paserk.keys.parse(allocator, paserk_str);
    defer decoded.deinit();
    try std.testing.expectEqual(version, decoded.version);
    try std.testing.expectEqual(kind, decoded.kind);
    try std.testing.expectEqualSlices(u8, buf[0..len], decoded.bytes);
}

fn runPieRoundTrip(s: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    const version = s.value(paseto.Version);
    const kind = s.value(paseto.paserk.pie.Kind);
    var wrapping: [32]u8 = undefined;
    s.bytes(&wrapping);
    const ptk_len: usize = switch (version) {
        .v3 => switch (kind) {
            .local => 32,
            .secret => 48,
        },
        .v4 => switch (kind) {
            .local => 32,
            .secret => 64,
        },
    };
    var ptk: [64]u8 = undefined;
    s.bytes(ptk[0..ptk_len]);

    const wrapped = try paseto.paserk.pie.wrap(allocator, version, kind, &wrapping, ptk[0..ptk_len], .{});
    defer allocator.free(wrapped);
    var out = try paseto.paserk.pie.unwrap(allocator, &wrapping, wrapped);
    defer out.deinit();
    try std.testing.expectEqual(version, out.version);
    try std.testing.expectEqual(kind, out.kind);
    try std.testing.expectEqualSlices(u8, ptk[0..ptk_len], out.bytes);
}

fn runPkeRoundTrip(s: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    const version = s.value(paseto.Version);
    var ptk: [32]u8 = undefined;
    s.bytes(&ptk);
    switch (version) {
        .v3 => {
            var scalar_seed: [48]u8 = undefined;
            s.bytes(&scalar_seed);
            const pk = try support.deriveValidV3Public(scalar_seed);
            const scalar = pk.secretBytes() orelse unreachable;
            const compressed = pk.publicCompressed();
            var ephemeral_seed: [48]u8 = undefined;
            s.bytes(&ephemeral_seed);
            const ephemeral = try support.deriveValidV3Public(ephemeral_seed);
            const ephemeral_scalar = ephemeral.secretBytes() orelse unreachable;
            const sealed = try paseto.paserk.pke.sealV3(allocator, &compressed, &ptk, ephemeral_scalar);
            defer allocator.free(sealed);
            const out = try paseto.paserk.pke.unsealV3(allocator, scalar, sealed);
            defer allocator.free(out);
            try std.testing.expectEqualSlices(u8, &ptk, out);
        },
        .v4 => {
            var seed: [32]u8 = undefined;
            s.bytes(&seed);
            const pk = try paseto.v4.Public.fromSeed(&seed);
            const recipient_pub = pk.publicKeyBytes();
            var ephemeral: [32]u8 = undefined;
            s.bytes(&ephemeral);
            ephemeral[0] &= 248;
            ephemeral[31] &= 127;
            ephemeral[31] |= 64;
            const sealed = try paseto.paserk.pke.sealV4(allocator, recipient_pub, &ptk, ephemeral);
            defer allocator.free(sealed);
            const out = try paseto.paserk.pke.unsealV4(allocator, seed, sealed);
            defer allocator.free(out);
            try std.testing.expectEqualSlices(u8, &ptk, out);
        },
    }
}

fn runPbkwRoundTrip(s: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    const version = s.value(paseto.Version);
    const kind = s.value(paseto.paserk.pbkw.Kind);
    const ptk_len: usize = switch (version) {
        .v3 => switch (kind) {
            .local => 32,
            .secret => 48,
        },
        .v4 => switch (kind) {
            .local => 32,
            .secret => 64,
        },
    };
    var ptk: [64]u8 = undefined;
    s.bytes(ptk[0..ptk_len]);
    var pw_buf: [32]u8 = undefined;
    const pw = pw_buf[0..s.slice(&pw_buf)];

    switch (version) {
        .v3 => {
            var salt: [32]u8 = undefined;
            s.bytes(&salt);
            var nonce: [16]u8 = undefined;
            s.bytes(&nonce);
            const wrapped = try paseto.paserk.pbkw.wrapV3(allocator, kind, pw, ptk[0..ptk_len], .{
                .params = support.PbkwV3FuzzParams,
                .salt = salt,
                .nonce = nonce,
            });
            defer allocator.free(wrapped);
            var out = try paseto.paserk.pbkw.unwrap(allocator, pw, wrapped);
            defer out.deinit();
            try std.testing.expectEqualSlices(u8, ptk[0..ptk_len], out.bytes);
        },
        .v4 => {
            var salt: [16]u8 = undefined;
            s.bytes(&salt);
            var nonce: [24]u8 = undefined;
            s.bytes(&nonce);
            const wrapped = try paseto.paserk.pbkw.wrapV4(allocator, kind, pw, ptk[0..ptk_len], .{
                .params = support.PbkwV4FuzzParams,
                .salt = salt,
                .nonce = nonce,
            });
            defer allocator.free(wrapped);
            var out = try paseto.paserk.pbkw.unwrap(allocator, pw, wrapped);
            defer out.deinit();
            try std.testing.expectEqualSlices(u8, ptk[0..ptk_len], out.bytes);
        },
    }
}

fn runMixedVersionMisuse(s: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    var key_buf: [32]u8 = undefined;
    s.bytes(&key_buf);
    const produce_v4 = s.value(bool);
    var msg_buf: [64]u8 = undefined;
    const msg = msg_buf[0..s.slice(&msg_buf)];

    if (produce_v4) {
        const v4k = try paseto.v4.Local.fromBytes(&key_buf);
        const tok = try v4k.encrypt(allocator, msg, .{});
        defer allocator.free(tok);
        const v3k = try paseto.v3.Local.fromBytes(&key_buf);
        if (v3k.decrypt(allocator, tok, "")) |ok| {
            allocator.free(ok);
            return error.MixedVersionShouldNotDecrypt;
        } else |err| try support.expectAllowed(err, &misuse_errors);
    } else {
        const v3k = try paseto.v3.Local.fromBytes(&key_buf);
        const tok = try v3k.encrypt(allocator, msg, .{});
        defer allocator.free(tok);
        const v4k = try paseto.v4.Local.fromBytes(&key_buf);
        if (v4k.decrypt(allocator, tok, "")) |ok| {
            allocator.free(ok);
            return error.MixedVersionShouldNotDecrypt;
        } else |err| try support.expectAllowed(err, &misuse_errors);
    }
}

fn runMixedPurposeMisuse(s: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    const version = s.value(paseto.Version);
    var msg_buf: [64]u8 = undefined;
    const msg = msg_buf[0..s.slice(&msg_buf)];

    switch (version) {
        .v4 => {
            // Produce a v4.local token; try to verify it via v4.Public.
            var key_buf: [32]u8 = undefined;
            s.bytes(&key_buf);
            const local = try paseto.v4.Local.fromBytes(&key_buf);
            const tok = try local.encrypt(allocator, msg, .{});
            defer allocator.free(tok);

            var seed: [32]u8 = undefined;
            s.bytes(&seed);
            const pk = try paseto.v4.Public.fromSeed(&seed);
            if (pk.verify(allocator, tok, "")) |ok| {
                allocator.free(ok);
                return error.MixedPurposeShouldNotVerify;
            } else |err| try support.expectAllowed(err, &misuse_errors);
        },
        .v3 => {
            var key_buf: [32]u8 = undefined;
            s.bytes(&key_buf);
            const local = try paseto.v3.Local.fromBytes(&key_buf);
            const tok = try local.encrypt(allocator, msg, .{});
            defer allocator.free(tok);

            var scalar: [48]u8 = undefined;
            s.bytes(&scalar);
            const pk = try support.deriveValidV3Public(scalar);
            if (pk.verify(allocator, tok, "")) |ok| {
                allocator.free(ok);
                return error.MixedPurposeShouldNotVerify;
            } else |err| try support.expectAllowed(err, &misuse_errors);
        },
    }
}

fn exerciseLocalMismatchV3(
    allocator: std.mem.Allocator,
    s: *std.testing.Smith,
    key_buf: [32]u8,
    assertion: []const u8,
    tok: []const u8,
    mismatch: MismatchClass,
) !void {
    const key = try paseto.v3.Local.fromBytes(&key_buf);
    switch (mismatch) {
        .wrong_version => {
            const tampered = try rewriteTokenHeader(allocator, tok, .v4, .local);
            defer allocator.free(tampered);
            try expectLocalRejectV3(key, tampered, assertion, error.WrongPurpose);
        },
        .wrong_purpose => {
            const tampered = try rewriteTokenHeader(allocator, tok, .v3, .public);
            defer allocator.free(tampered);
            try expectLocalRejectV3(key, tampered, assertion, error.WrongPurpose);
        },
        .wrong_key => {
            var wrong_key_buf = key_buf;
            wrong_key_buf[0] ^= 0xff;
            const wrong_key = try paseto.v3.Local.fromBytes(&wrong_key_buf);
            try expectLocalRejectV3(wrong_key, tok, assertion, error.InvalidAuthenticator);
        },
        .mutated_payload => {
            const tampered = try support.mutateToken(allocator, tok, .payload_byte, s);
            defer allocator.free(tampered);
            try expectLocalRejectV3(key, tampered, assertion, error.InvalidAuthenticator);
        },
        .mutated_authenticator_signature => {
            const tampered = try support.mutateToken(allocator, tok, .authenticator_byte, s);
            defer allocator.free(tampered);
            try expectLocalRejectV3(key, tampered, assertion, error.InvalidAuthenticator);
        },
        .malformed_framing => {
            const tampered = try makeMalformedToken(allocator, tok);
            defer allocator.free(tampered);
            try expectLocalRejectV3Allowed(key, tampered, assertion, &malformed_token_errors);
        },
    }
}

fn exerciseLocalMismatchV4(
    allocator: std.mem.Allocator,
    s: *std.testing.Smith,
    key_buf: [32]u8,
    assertion: []const u8,
    tok: []const u8,
    mismatch: MismatchClass,
) !void {
    const key = try paseto.v4.Local.fromBytes(&key_buf);
    switch (mismatch) {
        .wrong_version => {
            const tampered = try rewriteTokenHeader(allocator, tok, .v3, .local);
            defer allocator.free(tampered);
            try expectLocalRejectV4(key, tampered, assertion, error.WrongPurpose);
        },
        .wrong_purpose => {
            const tampered = try rewriteTokenHeader(allocator, tok, .v4, .public);
            defer allocator.free(tampered);
            try expectLocalRejectV4(key, tampered, assertion, error.WrongPurpose);
        },
        .wrong_key => {
            var wrong_key_buf = key_buf;
            wrong_key_buf[0] ^= 0xff;
            const wrong_key = try paseto.v4.Local.fromBytes(&wrong_key_buf);
            try expectLocalRejectV4(wrong_key, tok, assertion, error.InvalidAuthenticator);
        },
        .mutated_payload => {
            const tampered = try support.mutateToken(allocator, tok, .payload_byte, s);
            defer allocator.free(tampered);
            try expectLocalRejectV4(key, tampered, assertion, error.InvalidAuthenticator);
        },
        .mutated_authenticator_signature => {
            const tampered = try support.mutateToken(allocator, tok, .authenticator_byte, s);
            defer allocator.free(tampered);
            try expectLocalRejectV4(key, tampered, assertion, error.InvalidAuthenticator);
        },
        .malformed_framing => {
            const tampered = try makeMalformedToken(allocator, tok);
            defer allocator.free(tampered);
            try expectLocalRejectV4Allowed(key, tampered, assertion, &malformed_token_errors);
        },
    }
}

fn exercisePublicMismatchV3(
    allocator: std.mem.Allocator,
    s: *std.testing.Smith,
    signer_scalar: [48]u8,
    assertion: []const u8,
    tok: []const u8,
    mismatch: MismatchClass,
) !void {
    const signer = try support.deriveValidV3Public(signer_scalar);
    switch (mismatch) {
        .wrong_version => {
            const tampered = try rewriteTokenHeader(allocator, tok, .v4, .public);
            defer allocator.free(tampered);
            try expectPublicRejectV3(signer, tampered, assertion, error.WrongPurpose);
        },
        .wrong_purpose => {
            const tampered = try rewriteTokenHeader(allocator, tok, .v3, .local);
            defer allocator.free(tampered);
            try expectPublicRejectV3(signer, tampered, assertion, error.WrongPurpose);
        },
        .wrong_key => {
            var verifier_seed = signer_scalar;
            verifier_seed[0] ^= 0xff;
            const verifier = try support.deriveDistinctValidV3Public(verifier_seed, signer.publicCompressed());
            try expectPublicRejectV3(verifier, tok, assertion, error.InvalidSignature);
        },
        .mutated_payload => {
            const tampered = try support.mutateToken(allocator, tok, .payload_byte, s);
            defer allocator.free(tampered);
            try expectPublicRejectV3(signer, tampered, assertion, error.InvalidSignature);
        },
        .mutated_authenticator_signature => {
            const tampered = try support.mutateToken(allocator, tok, .authenticator_byte, s);
            defer allocator.free(tampered);
            try expectPublicRejectV3(signer, tampered, assertion, error.InvalidSignature);
        },
        .malformed_framing => {
            const tampered = try makeMalformedToken(allocator, tok);
            defer allocator.free(tampered);
            try expectPublicRejectV3Allowed(signer, tampered, assertion, &malformed_token_errors);
        },
    }
}

fn exercisePublicMismatchV4(
    allocator: std.mem.Allocator,
    s: *std.testing.Smith,
    seed: [32]u8,
    assertion: []const u8,
    tok: []const u8,
    mismatch: MismatchClass,
) !void {
    const signer = try paseto.v4.Public.fromSeed(&seed);
    switch (mismatch) {
        .wrong_version => {
            const tampered = try rewriteTokenHeader(allocator, tok, .v3, .public);
            defer allocator.free(tampered);
            try expectPublicRejectV4(signer, tampered, assertion, error.WrongPurpose);
        },
        .wrong_purpose => {
            const tampered = try rewriteTokenHeader(allocator, tok, .v4, .local);
            defer allocator.free(tampered);
            try expectPublicRejectV4(signer, tampered, assertion, error.WrongPurpose);
        },
        .wrong_key => {
            var other_seed = seed;
            other_seed[0] ^= 0xff;
            const verifier = try paseto.v4.Public.fromSeed(&other_seed);
            try expectPublicRejectV4(verifier, tok, assertion, error.InvalidSignature);
        },
        .mutated_payload => {
            const tampered = try support.mutateToken(allocator, tok, .payload_byte, s);
            defer allocator.free(tampered);
            try expectPublicRejectV4(signer, tampered, assertion, error.InvalidSignature);
        },
        .mutated_authenticator_signature => {
            const tampered = try support.mutateToken(allocator, tok, .authenticator_byte, s);
            defer allocator.free(tampered);
            try expectPublicRejectV4(signer, tampered, assertion, error.InvalidSignature);
        },
        .malformed_framing => {
            const tampered = try makeMalformedToken(allocator, tok);
            defer allocator.free(tampered);
            try expectPublicRejectV4Allowed(signer, tampered, assertion, &malformed_token_errors);
        },
    }
}

fn makeMalformedToken(allocator: std.mem.Allocator, tok: []const u8) ![]u8 {
    const suffix = ".Zm9v.Zm9v";
    const out = try allocator.alloc(u8, tok.len + suffix.len);
    errdefer allocator.free(out);
    @memcpy(out[0..tok.len], tok);
    @memcpy(out[tok.len..], suffix);
    return out;
}

fn rewriteTokenHeader(
    allocator: std.mem.Allocator,
    tok: []const u8,
    version: paseto.Version,
    purpose: paseto.Purpose,
) ![]u8 {
    var parsed = try paseto.token.parse(allocator, tok);
    defer parsed.deinit();
    return try paseto.token.serialize(allocator, version, purpose, parsed.payload, parsed.footer);
}

fn expectLocalRejectV3(key: paseto.v3.Local, tok: []const u8, assertion: []const u8, expected: paseto.Error) !void {
    if (key.decrypt(std.testing.allocator, tok, assertion)) |ok| {
        std.testing.allocator.free(ok);
        return error.ExpectedLocalReject;
    } else |err| try std.testing.expectEqual(expected, err);
}

fn expectLocalRejectV4(key: paseto.v4.Local, tok: []const u8, assertion: []const u8, expected: paseto.Error) !void {
    if (key.decrypt(std.testing.allocator, tok, assertion)) |ok| {
        std.testing.allocator.free(ok);
        return error.ExpectedLocalReject;
    } else |err| try std.testing.expectEqual(expected, err);
}

fn expectLocalRejectV3Allowed(key: paseto.v3.Local, tok: []const u8, assertion: []const u8, allowed: []const paseto.Error) !void {
    if (key.decrypt(std.testing.allocator, tok, assertion)) |ok| {
        std.testing.allocator.free(ok);
        return error.ExpectedLocalReject;
    } else |err| try support.expectAllowed(err, allowed);
}

fn expectLocalRejectV4Allowed(key: paseto.v4.Local, tok: []const u8, assertion: []const u8, allowed: []const paseto.Error) !void {
    if (key.decrypt(std.testing.allocator, tok, assertion)) |ok| {
        std.testing.allocator.free(ok);
        return error.ExpectedLocalReject;
    } else |err| try support.expectAllowed(err, allowed);
}

fn expectPublicRejectV3(key: paseto.v3.Public, tok: []const u8, assertion: []const u8, expected: paseto.Error) !void {
    if (key.verify(std.testing.allocator, tok, assertion)) |ok| {
        std.testing.allocator.free(ok);
        return error.ExpectedPublicReject;
    } else |err| try std.testing.expectEqual(expected, err);
}

fn expectPublicRejectV4(key: paseto.v4.Public, tok: []const u8, assertion: []const u8, expected: paseto.Error) !void {
    if (key.verify(std.testing.allocator, tok, assertion)) |ok| {
        std.testing.allocator.free(ok);
        return error.ExpectedPublicReject;
    } else |err| try std.testing.expectEqual(expected, err);
}

fn expectPublicRejectV3Allowed(key: paseto.v3.Public, tok: []const u8, assertion: []const u8, allowed: []const paseto.Error) !void {
    if (key.verify(std.testing.allocator, tok, assertion)) |ok| {
        std.testing.allocator.free(ok);
        return error.ExpectedPublicReject;
    } else |err| try support.expectAllowed(err, allowed);
}

fn expectPublicRejectV4Allowed(key: paseto.v4.Public, tok: []const u8, assertion: []const u8, allowed: []const paseto.Error) !void {
    if (key.verify(std.testing.allocator, tok, assertion)) |ok| {
        std.testing.allocator.free(ok);
        return error.ExpectedPublicReject;
    } else |err| try support.expectAllowed(err, allowed);
}
