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
    @embedFile("corpus/scenarios/seed_01.bin"),
    @embedFile("corpus/scenarios/seed_02.bin"),
    @embedFile("corpus/scenarios/seed_03.bin"),
    @embedFile("corpus/scenarios/seed_04.bin"),
    @embedFile("corpus/scenarios/seed_05.bin"),
    @embedFile("corpus/scenarios/seed_06.bin"),
    @embedFile("corpus/scenarios/seed_07.bin"),
    @embedFile("corpus/scenarios/seed_08.bin"),
    @embedFile("corpus/scenarios/seed_09.bin"),
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

const local_mutation_errors = [_]paseto.Error{
    error.InvalidToken,
    error.WrongPurpose,
    error.InvalidAuthenticator,
    error.MessageTooShort,
    error.InvalidBase64,
    error.InvalidPadding,
    error.UnsupportedVersion,
    error.UnsupportedPurpose,
    error.OutOfMemory,
};

const public_mutation_errors = [_]paseto.Error{
    error.InvalidToken,
    error.WrongPurpose,
    error.InvalidSignature,
    error.MessageTooShort,
    error.InvalidBase64,
    error.InvalidPadding,
    error.UnsupportedVersion,
    error.UnsupportedPurpose,
    error.OutOfMemory,
};

const mixed_version_errors = [_]paseto.Error{
    error.WrongPurpose,
    error.InvalidEncoding,
    error.UnsupportedVersion,
    error.UnsupportedPurpose,
    error.UnsupportedOperation,
    error.InvalidToken,
    error.InvalidAuthenticator,
    error.InvalidSignature,
    error.MessageTooShort,
    error.OutOfMemory,
};

const mixed_purpose_errors = [_]paseto.Error{
    error.WrongPurpose,
    error.InvalidToken,
    error.InvalidAuthenticator,
    error.InvalidSignature,
    error.MessageTooShort,
    error.OutOfMemory,
};

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

    switch (version) {
        .v3 => {
            const key = try paseto.v3.Local.fromBytes(&key_buf);
            const tok = try key.encrypt(allocator, msg, .{
                .footer = footer,
                .implicit_assertion = assertion,
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
            const pk = paseto.v3.Public.fromScalarBytes(&scalar) catch return;
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
    var key_buf: [32]u8 = undefined;
    s.bytes(&key_buf);
    var msg_buf: [128]u8 = undefined;
    const msg = msg_buf[0..s.slice(&msg_buf)];
    var footer_buf: [32]u8 = undefined;
    const footer = footer_buf[0..s.slice(&footer_buf)];

    switch (version) {
        .v3 => {
            const key = try paseto.v3.Local.fromBytes(&key_buf);
            const tok = try key.encrypt(allocator, msg, .{ .footer = footer });
            defer allocator.free(tok);
            const mutation = support.pickMutation(s);
            const tampered = try support.mutateToken(allocator, tok, mutation, s);
            defer allocator.free(tampered);
            if (std.mem.eql(u8, tampered, tok)) return;
            if (key.decrypt(allocator, tampered, "")) |ok| {
                allocator.free(ok);
                return error.MutatedTokenShouldNotDecrypt;
            } else |err| try support.expectAllowed(err, &local_mutation_errors);
        },
        .v4 => {
            const key = try paseto.v4.Local.fromBytes(&key_buf);
            const tok = try key.encrypt(allocator, msg, .{ .footer = footer });
            defer allocator.free(tok);
            const mutation = support.pickMutation(s);
            const tampered = try support.mutateToken(allocator, tok, mutation, s);
            defer allocator.free(tampered);
            if (std.mem.eql(u8, tampered, tok)) return;
            if (key.decrypt(allocator, tampered, "")) |ok| {
                allocator.free(ok);
                return error.MutatedTokenShouldNotDecrypt;
            } else |err| try support.expectAllowed(err, &local_mutation_errors);
        },
    }
}

fn runPublicMutationReject(s: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    const version = s.value(paseto.Version);
    var msg_buf: [128]u8 = undefined;
    const msg = msg_buf[0..s.slice(&msg_buf)];
    var footer_buf: [32]u8 = undefined;
    const footer = footer_buf[0..s.slice(&footer_buf)];

    switch (version) {
        .v3 => {
            var scalar: [48]u8 = undefined;
            s.bytes(&scalar);
            const pk = paseto.v3.Public.fromScalarBytes(&scalar) catch return;
            const tok = try pk.sign(allocator, msg, .{ .footer = footer });
            defer allocator.free(tok);
            const mutation = support.pickMutation(s);
            const tampered = try support.mutateToken(allocator, tok, mutation, s);
            defer allocator.free(tampered);
            if (std.mem.eql(u8, tampered, tok)) return;
            if (pk.verify(allocator, tampered, "")) |ok| {
                allocator.free(ok);
                return error.MutatedTokenShouldNotVerify;
            } else |err| try support.expectAllowed(err, &public_mutation_errors);
        },
        .v4 => {
            var seed: [32]u8 = undefined;
            s.bytes(&seed);
            const pk = try paseto.v4.Public.fromSeed(&seed);
            const tok = try pk.sign(allocator, msg, .{ .footer = footer });
            defer allocator.free(tok);
            const mutation = support.pickMutation(s);
            const tampered = try support.mutateToken(allocator, tok, mutation, s);
            defer allocator.free(tampered);
            if (std.mem.eql(u8, tampered, tok)) return;
            if (pk.verify(allocator, tampered, "")) |ok| {
                allocator.free(ok);
                return error.MutatedTokenShouldNotVerify;
            } else |err| try support.expectAllowed(err, &public_mutation_errors);
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
            var scalar: [48]u8 = undefined;
            s.bytes(&scalar);
            const pk = paseto.v3.Public.fromScalarBytes(&scalar) catch return;
            const compressed = pk.publicCompressed();
            const sealed = paseto.paserk.pke.sealV3(allocator, &compressed, &ptk, null) catch return;
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
            const sealed = try paseto.paserk.pke.sealV4(allocator, recipient_pub, &ptk, null);
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
        } else |err| try support.expectAllowed(err, &mixed_version_errors);
    } else {
        const v3k = try paseto.v3.Local.fromBytes(&key_buf);
        const tok = try v3k.encrypt(allocator, msg, .{});
        defer allocator.free(tok);
        const v4k = try paseto.v4.Local.fromBytes(&key_buf);
        if (v4k.decrypt(allocator, tok, "")) |ok| {
            allocator.free(ok);
            return error.MixedVersionShouldNotDecrypt;
        } else |err| try support.expectAllowed(err, &mixed_version_errors);
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
            } else |err| try support.expectAllowed(err, &mixed_purpose_errors);
        },
        .v3 => {
            var key_buf: [32]u8 = undefined;
            s.bytes(&key_buf);
            const local = try paseto.v3.Local.fromBytes(&key_buf);
            const tok = try local.encrypt(allocator, msg, .{});
            defer allocator.free(tok);

            var scalar: [48]u8 = undefined;
            s.bytes(&scalar);
            const pk = paseto.v3.Public.fromScalarBytes(&scalar) catch return;
            if (pk.verify(allocator, tok, "")) |ok| {
                allocator.free(ok);
                return error.MixedPurposeShouldNotVerify;
            } else |err| try support.expectAllowed(err, &mixed_purpose_errors);
        },
    }
}
