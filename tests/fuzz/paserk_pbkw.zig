//! Fuzz harness for `src/paserk/pbkw.zig`. Sub-targets:
//!   - `unwrap` on arbitrary bytes
//!   - v4 and v3 wrap/unwrap round-trips with bounded fuzz-mode params
//!   - explicit negative test: wrap with non-KiB-aligned memlimit → WeakParameters

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds_unwrap = [_][]const u8{
    @embedFile("corpus/paserk_pbkw/k3_local_pw.bin"),
    @embedFile("corpus/paserk_pbkw/k3_secret_pw.bin"),
    @embedFile("corpus/paserk_pbkw/k4_local_pw.bin"),
    @embedFile("corpus/paserk_pbkw/k4_secret_pw.bin"),
    @embedFile("corpus/paserk_pbkw/short.bin"),
    @embedFile("corpus/paserk_pbkw/bad_version.bin"),
};

const unwrap_errors = [_]paseto.Error{
    error.InvalidEncoding,
    error.UnsupportedVersion,
    error.UnsupportedOperation,
    error.InvalidKey,
    error.InvalidAuthenticator,
    error.MessageTooShort,
    error.WeakParameters,
    error.Canceled,
    error.OutOfMemory,
    error.InvalidBase64,
    error.InvalidPadding,
};

test "fuzz: pbkw.unwrap" {
    try std.testing.fuzz({}, unwrapFuzz, .{ .corpus = &seeds_unwrap });
}

test "fuzz: pbkw k3.local-pw wrap/unwrap round-trip" {
    try std.testing.fuzz({}, roundTripV3LocalFuzz, .{});
}

test "fuzz: pbkw k3.secret-pw wrap/unwrap round-trip" {
    try std.testing.fuzz({}, roundTripV3SecretFuzz, .{});
}

test "fuzz: pbkw k4.local-pw wrap/unwrap round-trip" {
    try std.testing.fuzz({}, roundTripV4LocalFuzz, .{});
}

test "fuzz: pbkw k4.secret-pw wrap/unwrap round-trip" {
    try std.testing.fuzz({}, roundTripV4SecretFuzz, .{});
}

test "pbkw: wrapV4 rejects non-kib-aligned memlimit" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = @splat(0x11);
    try std.testing.expectError(paseto.Error.WeakParameters, paseto.paserk.pbkw.wrapV4(
        allocator,
        .local,
        "pw",
        &key,
        .{
            .params = .{ .memlimit_bytes = 1500, .opslimit = 2, .para = 1 },
            .salt = @as([16]u8, @splat(0x22)),
            .nonce = @as([24]u8, @splat(0x33)),
        },
    ));
}

fn unwrapFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var input_buf: [support.max_input_bytes]u8 = undefined;
    const input_n = s.slice(&input_buf);
    const input = input_buf[0..input_n];

    var pw_buf: [64]u8 = undefined;
    const pw_n = s.slice(&pw_buf);
    const password = pw_buf[0..pw_n];

    const allocator = std.testing.allocator;
    var out = paseto.paserk.pbkw.unwrap(allocator, password, input) catch |err| {
        return support.expectAllowed(err, &unwrap_errors);
    };
    defer out.deinit();
    try std.testing.expect(out.bytes.len > 0);
}

fn roundTripV4LocalFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    try roundTripV4Kind(.local, s);
}

fn roundTripV4SecretFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    try roundTripV4Kind(.secret, s);
}

fn roundTripV4Kind(kind: paseto.paserk.pbkw.Kind, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;

    var pw_buf: [32]u8 = undefined;
    const pw_n = s.slice(&pw_buf);
    const password = pw_buf[0..pw_n];

    var ptk: [64]u8 = undefined;
    const ptk_slice = try fillV4Ptk(kind, s, &ptk);
    var salt: [16]u8 = undefined;
    s.bytes(&salt);
    var nonce: [24]u8 = undefined;
    s.bytes(&nonce);

    const wrapped = try paseto.paserk.pbkw.wrapV4(allocator, kind, password, ptk_slice, .{
        .params = support.PbkwV4FuzzParams,
        .policy = paseto.paserk.pbkw.Policy.testing,
        .salt = salt,
        .nonce = nonce,
    });
    defer allocator.free(wrapped);

    var unwrapped = try paseto.paserk.pbkw.unwrapWithPolicy(allocator, password, wrapped, .testing);
    defer unwrapped.deinit();
    try std.testing.expectEqual(.v4, unwrapped.version);
    try std.testing.expectEqual(kind, unwrapped.kind);
    try std.testing.expectEqualSlices(u8, ptk_slice, unwrapped.bytes);
}

fn roundTripV3LocalFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    try roundTripV3Kind(.local, s);
}

fn roundTripV3SecretFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    try roundTripV3Kind(.secret, s);
}

fn roundTripV3Kind(kind: paseto.paserk.pbkw.Kind, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;

    var pw_buf: [32]u8 = undefined;
    const pw_n = s.slice(&pw_buf);
    const password = pw_buf[0..pw_n];

    var ptk: [64]u8 = undefined;
    const ptk_slice = try fillV3Ptk(kind, s, &ptk);
    var salt: [32]u8 = undefined;
    s.bytes(&salt);
    var nonce: [16]u8 = undefined;
    s.bytes(&nonce);

    const wrapped = try paseto.paserk.pbkw.wrapV3(allocator, kind, password, ptk_slice, .{
        .params = support.PbkwV3FuzzParams,
        .policy = paseto.paserk.pbkw.Policy.testing,
        .salt = salt,
        .nonce = nonce,
    });
    defer allocator.free(wrapped);

    var unwrapped = try paseto.paserk.pbkw.unwrapWithPolicy(allocator, password, wrapped, .testing);
    defer unwrapped.deinit();
    try std.testing.expectEqual(.v3, unwrapped.version);
    try std.testing.expectEqual(kind, unwrapped.kind);
    try std.testing.expectEqualSlices(u8, ptk_slice, unwrapped.bytes);
}

fn fillV4Ptk(
    kind: paseto.paserk.pbkw.Kind,
    s: *std.testing.Smith,
    ptk: *[64]u8,
) ![]const u8 {
    switch (kind) {
        .local => {
            s.bytes(ptk[0..32]);
            return ptk[0..32];
        },
        .secret => {
            var seed: [32]u8 = undefined;
            defer paseto.util.secureZero(&seed);
            s.bytes(&seed);
            const key = try paseto.v4.Public.fromSeed(&seed);
            var secret = key.secretKeyBytes().?;
            defer paseto.util.secureZero(&secret);
            @memcpy(ptk[0..64], &secret);
            return ptk[0..64];
        },
    }
}

fn fillV3Ptk(
    kind: paseto.paserk.pbkw.Kind,
    s: *std.testing.Smith,
    ptk: *[64]u8,
) ![]const u8 {
    switch (kind) {
        .local => {
            s.bytes(ptk[0..32]);
            return ptk[0..32];
        },
        .secret => {
            s.bytes(ptk[0..48]);
            var attempts: usize = 0;
            while (attempts < 1024) : (attempts += 1) {
                _ = paseto.v3.Public.fromScalarBytes(ptk[0..48]) catch {
                    incrementBigEndian(ptk[0..48]);
                    continue;
                };
                return ptk[0..48];
            }

            const fallback = [_]u8{
                0x20, 0x34, 0x76, 0x09, 0x60, 0x74, 0x77, 0xac,
                0xa8, 0xfb, 0xfb, 0xc5, 0xe6, 0x21, 0x84, 0x55,
                0xf3, 0x19, 0x96, 0x69, 0x79, 0x2e, 0xf8, 0xb4,
                0x66, 0xfa, 0xa8, 0x7b, 0xdc, 0x67, 0x79, 0x81,
                0x44, 0xc8, 0x48, 0xdd, 0x03, 0x66, 0x1e, 0xed,
                0x5a, 0xc6, 0x24, 0x61, 0x34, 0x0c, 0xea, 0x96,
            };
            @memcpy(ptk[0..48], &fallback);
            return ptk[0..48];
        },
    }
}

fn incrementBigEndian(buf: []u8) void {
    var i = buf.len;
    while (i > 0) {
        i -= 1;
        buf[i] +%= 1;
        if (buf[i] != 0) break;
    }
}
