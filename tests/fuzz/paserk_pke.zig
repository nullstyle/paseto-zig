//! Fuzz harness for `src/paserk/pke.zig`. Sub-targets:
//!   - `unsealV3` / `unsealV4` / `unsealV4FromSecretKey` on arbitrary bytes
//!   - v3 and v4 seal/unseal round-trips
//!   - v4 mutation reject

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds_unseal = [_][]const u8{
    @embedFile("corpus/paserk_pke/k4_seal_valid.bin"),
    @embedFile("corpus/paserk_pke/k3_seal_valid.bin"),
    @embedFile("corpus/paserk_pke/short.bin"),
    @embedFile("corpus/paserk_pke/bad_version.bin"),
};

const unseal_errors = [_]paseto.Error{
    error.InvalidEncoding,
    error.InvalidKey,
    error.InvalidAuthenticator,
    error.MessageTooShort,
    error.InvalidBase64,
    error.InvalidPadding,
    error.OutOfMemory,
};

test "fuzz: pke.unsealV4" {
    try std.testing.fuzz({}, unsealV4Fuzz, .{ .corpus = &seeds_unseal });
}

test "fuzz: pke.unsealV4FromSecretKey" {
    try std.testing.fuzz({}, unsealV4SecretFuzz, .{ .corpus = &seeds_unseal });
}

test "fuzz: pke.unsealV3" {
    try std.testing.fuzz({}, unsealV3Fuzz, .{ .corpus = &seeds_unseal });
}

test "fuzz: pke v4 seal/unseal round-trip" {
    try std.testing.fuzz({}, roundTripV4Fuzz, .{});
}

test "fuzz: pke v3 seal/unseal round-trip" {
    try std.testing.fuzz({}, roundTripV3Fuzz, .{});
}

test "fuzz: pke v4 mutation reject" {
    try std.testing.fuzz({}, mutationV4Fuzz, .{});
}

test "fuzz: pke v3 mutation reject" {
    try std.testing.fuzz({}, mutationV3Fuzz, .{});
}

fn unsealV4Fuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var input_buf: [support.max_input_bytes]u8 = undefined;
    const input_n = s.slice(&input_buf);
    const input = input_buf[0..input_n];

    var seed: [32]u8 = undefined;
    s.bytes(&seed);

    const allocator = std.testing.allocator;
    const out = paseto.paserk.pke.unsealV4(allocator, seed, input) catch |err| {
        return support.expectAllowed(err, &unseal_errors);
    };
    defer allocator.free(out);
    try std.testing.expectEqual(@as(usize, 32), out.len);
}

fn unsealV4SecretFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var input_buf: [support.max_input_bytes]u8 = undefined;
    const input_n = s.slice(&input_buf);
    const input = input_buf[0..input_n];

    var secret: [64]u8 = undefined;
    s.bytes(&secret);

    const allocator = std.testing.allocator;
    const out = paseto.paserk.pke.unsealV4FromSecretKey(allocator, secret, input) catch |err| {
        return support.expectAllowed(err, &unseal_errors);
    };
    defer allocator.free(out);
    try std.testing.expectEqual(@as(usize, 32), out.len);
}

fn unsealV3Fuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var input_buf: [support.max_input_bytes]u8 = undefined;
    const input_n = s.slice(&input_buf);
    const input = input_buf[0..input_n];

    var scalar: [48]u8 = undefined;
    s.bytes(&scalar);

    const allocator = std.testing.allocator;
    const out = paseto.paserk.pke.unsealV3(allocator, scalar, input) catch |err| {
        return support.expectAllowed(err, &unseal_errors);
    };
    defer allocator.free(out);
    try std.testing.expectEqual(@as(usize, 32), out.len);
}

fn roundTripV4Fuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;

    // Fixed recipient keypair derived from a Smith seed so every iteration is
    // deterministic given the same Smith input.
    var seed: [32]u8 = undefined;
    s.bytes(&seed);
    const pk = try paseto.v4.Public.fromSeed(&seed);
    const recipient_pub = pk.publicKeyBytes();

    var ptk: [32]u8 = undefined;
    s.bytes(&ptk);
    var ephemeral: [32]u8 = undefined;
    s.bytes(&ephemeral);
    ephemeral[0] &= 248;
    ephemeral[31] &= 127;
    ephemeral[31] |= 64;

    const sealed = try paseto.paserk.pke.sealV4(allocator, recipient_pub, &ptk, ephemeral);
    defer allocator.free(sealed);

    const recovered = try paseto.paserk.pke.unsealV4(allocator, seed, sealed);
    defer allocator.free(recovered);
    try std.testing.expectEqualSlices(u8, &ptk, recovered);
}

fn roundTripV3Fuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;

    const pk = try paseto.v3.Public.generate();
    const scalar_bytes = pk.secretBytes() orelse unreachable;
    const pub_compressed = pk.publicCompressed();

    var ptk: [32]u8 = undefined;
    s.bytes(&ptk);

    const sealed = try paseto.paserk.pke.sealV3(allocator, &pub_compressed, &ptk, null);
    defer allocator.free(sealed);

    const recovered = try paseto.paserk.pke.unsealV3(allocator, scalar_bytes, sealed);
    defer allocator.free(recovered);
    try std.testing.expectEqualSlices(u8, &ptk, recovered);
}

fn mutationV4Fuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;

    var seed: [32]u8 = undefined;
    s.bytes(&seed);
    const pk = try paseto.v4.Public.fromSeed(&seed);
    const recipient_pub = pk.publicKeyBytes();
    const secret = pk.secretKeyBytes() orelse unreachable;

    var ptk: [32]u8 = undefined;
    s.bytes(&ptk);

    const sealed = try paseto.paserk.pke.sealV4(allocator, recipient_pub, &ptk, null);
    defer allocator.free(sealed);
    if (sealed.len <= 8) return; // need at least header + a body byte

    const tampered = try support.mutatePaserkBody(allocator, sealed, "k4.seal.", s);
    defer allocator.free(tampered);
    if (std.mem.eql(u8, tampered, sealed)) return;

    if (paseto.paserk.pke.unsealV4(allocator, seed, tampered)) |ok| {
        allocator.free(ok);
        return error.MutatedSealShouldNotUnseal;
    } else |err| {
        try support.expectAllowed(err, &unseal_errors);
    }

    if (paseto.paserk.pke.unsealV4FromSecretKey(allocator, secret, tampered)) |ok| {
        allocator.free(ok);
        return error.MutatedSealShouldNotUnsealWithSecretKey;
    } else |err| {
        try support.expectAllowed(err, &unseal_errors);
    }
}

fn mutationV3Fuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;

    const pk = try paseto.v3.Public.generate();
    const scalar = pk.secretBytes() orelse unreachable;
    const recipient_pub = pk.publicCompressed();

    var ptk: [32]u8 = undefined;
    s.bytes(&ptk);

    const sealed = try paseto.paserk.pke.sealV3(allocator, &recipient_pub, &ptk, null);
    defer allocator.free(sealed);

    const tampered = try support.mutatePaserkBody(allocator, sealed, "k3.seal.", s);
    defer allocator.free(tampered);
    if (std.mem.eql(u8, tampered, sealed)) return;

    if (paseto.paserk.pke.unsealV3(allocator, scalar, tampered)) |ok| {
        allocator.free(ok);
        return error.MutatedSealShouldNotUnseal;
    } else |err| {
        try support.expectAllowed(err, &unseal_errors);
    }
}
