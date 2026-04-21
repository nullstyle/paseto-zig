//! Fuzz harness for `src/paserk/pbkw.zig`. Sub-targets:
//!   - `unwrap` on arbitrary bytes
//!   - v4 and v3 wrap/unwrap round-trips with bounded fuzz-mode params
//!   - explicit negative test: wrap with non-KiB-aligned memlimit → WeakParameters

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds_unwrap = [_][]const u8{
    @embedFile("corpus/paserk_pbkw/k4_local_pw.bin"),
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

const wrap_errors = [_]paseto.Error{
    error.InvalidKey,
    error.WeakParameters,
    error.Canceled,
    error.OutOfMemory,
};

test "fuzz: pbkw.unwrap" {
    try std.testing.fuzz({}, unwrapFuzz, .{ .corpus = &seeds_unwrap });
}

test "fuzz: pbkw v4 wrap/unwrap round-trip" {
    try std.testing.fuzz({}, roundTripV4Fuzz, .{});
}

test "fuzz: pbkw v3 wrap/unwrap round-trip" {
    try std.testing.fuzz({}, roundTripV3Fuzz, .{});
}

test "pbkw: wrapV4 rejects non-kib-aligned memlimit" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x11} ** 32;
    try std.testing.expectError(paseto.Error.WeakParameters, paseto.paserk.pbkw.wrapV4(
        allocator,
        .local,
        "pw",
        &key,
        .{
            .params = .{ .memlimit_bytes = 1500, .opslimit = 2, .para = 1 },
            .salt = [_]u8{0x22} ** 16,
            .nonce = [_]u8{0x33} ** 24,
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

fn roundTripV4Fuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;

    var pw_buf: [32]u8 = undefined;
    const pw_n = s.slice(&pw_buf);
    const password = pw_buf[0..pw_n];

    var ptk: [32]u8 = undefined;
    s.bytes(&ptk);
    var salt: [16]u8 = undefined;
    s.bytes(&salt);
    var nonce: [24]u8 = undefined;
    s.bytes(&nonce);

    const wrapped = paseto.paserk.pbkw.wrapV4(allocator, .local, password, &ptk, .{
        .params = support.PbkwV4FuzzParams,
        .salt = salt,
        .nonce = nonce,
    }) catch |err| {
        return support.expectAllowed(err, &wrap_errors);
    };
    defer allocator.free(wrapped);

    var unwrapped = try paseto.paserk.pbkw.unwrap(allocator, password, wrapped);
    defer unwrapped.deinit();
    try std.testing.expectEqualSlices(u8, &ptk, unwrapped.bytes);
}

fn roundTripV3Fuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;

    var pw_buf: [32]u8 = undefined;
    const pw_n = s.slice(&pw_buf);
    const password = pw_buf[0..pw_n];

    var ptk: [32]u8 = undefined;
    s.bytes(&ptk);
    var salt: [32]u8 = undefined;
    s.bytes(&salt);
    var nonce: [16]u8 = undefined;
    s.bytes(&nonce);

    const wrapped = paseto.paserk.pbkw.wrapV3(allocator, .local, password, &ptk, .{
        .params = support.PbkwV3FuzzParams,
        .salt = salt,
        .nonce = nonce,
    }) catch |err| {
        return support.expectAllowed(err, &wrap_errors);
    };
    defer allocator.free(wrapped);

    var unwrapped = try paseto.paserk.pbkw.unwrap(allocator, password, wrapped);
    defer unwrapped.deinit();
    try std.testing.expectEqualSlices(u8, &ptk, unwrapped.bytes);
}
