//! Fuzz harness for `src/paserk/pie.zig`. Three sub-targets:
//!   - `pie.unwrap` on arbitrary bytes
//!   - wrap/unwrap round-trip with Smith-chosen inputs
//!   - mutation reject: wrap, flip bytes in the body, expect rejection

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds_unwrap = [_][]const u8{
    @embedFile("corpus/paserk_pie/k4_local_valid.bin"),
    @embedFile("corpus/paserk_pie/k3_secret_valid.bin"),
    @embedFile("corpus/paserk_pie/short.bin"),
    @embedFile("corpus/paserk_pie/bad_alg.bin"),
};

const unwrap_errors = [_]paseto.Error{
    error.InvalidEncoding,
    error.UnsupportedVersion,
    error.UnsupportedOperation,
    error.InvalidKey,
    error.InvalidAuthenticator,
    error.MessageTooShort,
    error.InvalidBase64,
    error.InvalidPadding,
    error.OutOfMemory,
};

test "fuzz: pie.unwrap" {
    try std.testing.fuzz({}, unwrapFuzz, .{ .corpus = &seeds_unwrap });
}

test "fuzz: pie wrap/unwrap round-trip" {
    try std.testing.fuzz({}, roundTripFuzz, .{});
}

test "fuzz: pie mutation reject" {
    try std.testing.fuzz({}, mutationFuzz, .{});
}

fn unwrapFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var input_buf: [support.max_input_bytes]u8 = undefined;
    const input_n = s.slice(&input_buf);
    const input = input_buf[0..input_n];

    var key_buf: [32]u8 = undefined;
    s.bytes(&key_buf);

    const allocator = std.testing.allocator;

    var result = paseto.paserk.pie.unwrap(allocator, &key_buf, input) catch |err| {
        return support.expectAllowed(err, &unwrap_errors);
    };
    defer result.deinit();
    try std.testing.expect(result.bytes.len > 0);
}

fn roundTripFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var wrapping: [32]u8 = undefined;
    s.bytes(&wrapping);

    const kind = s.value(paseto.paserk.pie.Kind);
    const version = s.value(paseto.Version);
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

    var ptk_buf: [64]u8 = undefined;
    s.bytes(ptk_buf[0..ptk_len]);

    var nonce: [32]u8 = undefined;
    s.bytes(&nonce);

    const wrapped = try paseto.paserk.pie.wrap(
        allocator,
        version,
        kind,
        &wrapping,
        ptk_buf[0..ptk_len],
        .{ .nonce = nonce },
    );
    defer allocator.free(wrapped);

    var unwrapped = try paseto.paserk.pie.unwrap(allocator, &wrapping, wrapped);
    defer unwrapped.deinit();

    try std.testing.expectEqual(version, unwrapped.version);
    try std.testing.expectEqual(kind, unwrapped.kind);
    try std.testing.expectEqualSlices(u8, ptk_buf[0..ptk_len], unwrapped.bytes);
}

fn mutationFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;

    var wrapping: [32]u8 = undefined;
    s.bytes(&wrapping);

    const version = s.value(paseto.Version);
    const ptk_len: usize = switch (version) {
        .v3 => 32,
        .v4 => 32,
    };
    var ptk: [32]u8 = undefined;
    s.bytes(ptk[0..ptk_len]);

    const wrapped = try paseto.paserk.pie.wrap(
        allocator,
        version,
        .local,
        &wrapping,
        ptk[0..ptk_len],
        .{},
    );
    defer allocator.free(wrapped);
    if (wrapped.len == 0) return;

    const tampered = try allocator.dupe(u8, wrapped);
    defer allocator.free(tampered);

    // Flip a byte strictly inside the body (past the "k{3,4}.local-wrap.pie."
    // header). The header has 18 ASCII chars — guard if the whole string is
    // somehow shorter.
    const header_len: usize = if (version == .v4) 18 else 18; // identical for v3/v4
    if (tampered.len <= header_len) return;
    const body_idx = s.valueRangeLessThan(u64, @intCast(header_len), @intCast(tampered.len));
    tampered[@intCast(body_idx)] ^= 0xff;

    if (paseto.paserk.pie.unwrap(allocator, &wrapping, tampered)) |ok| {
        var mut = ok;
        mut.deinit();
        return error.MutatedWrapShouldNotUnwrap;
    } else |err| {
        try support.expectAllowed(err, &unwrap_errors);
    }
}
