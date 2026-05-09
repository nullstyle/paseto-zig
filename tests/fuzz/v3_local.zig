//! Fuzz harness for `src/v3/local.zig`. Sub-targets:
//!   - `decrypt` on arbitrary bytes
//!   - encrypt/decrypt round-trip
//!   - mutation reject via `support.mutateToken`

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds_decrypt = [_][]const u8{
    @embedFile("corpus/v3_local/valid.bin"),
    @embedFile("corpus/v3_local/short.bin"),
    @embedFile("corpus/v3_local/wrong_purpose.bin"),
};

test "fuzz: v3.Local.decrypt" {
    try std.testing.fuzz({}, decryptFuzz, .{ .corpus = &seeds_decrypt });
}

test "fuzz: v3.Local encrypt/decrypt round-trip" {
    try std.testing.fuzz({}, roundTripFuzz, .{});
}

test "fuzz: v3.Local mutation reject" {
    try std.testing.fuzz({}, mutationFuzz, .{});
}

test "fuzz: v3.Local wrong-key reject" {
    try std.testing.fuzz({}, wrongKeyFuzz, .{});
}

fn decryptFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var tok_buf: [support.max_input_bytes]u8 = undefined;
    const n = s.slice(&tok_buf);
    const token_str = tok_buf[0..n];

    var key_buf: [32]u8 = undefined;
    s.bytes(&key_buf);
    const key = paseto.v3.Local.fromBytes(&key_buf) catch return;

    var assertion_buf: [64]u8 = undefined;
    const a_n = s.slice(&assertion_buf);

    const allocator = std.testing.allocator;
    const out = key.decrypt(allocator, token_str, assertion_buf[0..a_n]) catch |err| {
        return support.expectAllowed(err, &support.local_decrypt_errors);
    };
    defer allocator.free(out);
}

fn roundTripFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var key_buf: [32]u8 = undefined;
    s.bytes(&key_buf);
    const key = try paseto.v3.Local.fromBytes(&key_buf);

    var msg_buf: [1024]u8 = undefined;
    const msg_n = s.slice(&msg_buf);
    const message = msg_buf[0..msg_n];
    var footer_buf: [256]u8 = undefined;
    const f_n = s.slice(&footer_buf);
    const footer = footer_buf[0..f_n];
    var assertion_buf: [256]u8 = undefined;
    const a_n = s.slice(&assertion_buf);
    const assertion = assertion_buf[0..a_n];

    var nonce: [32]u8 = undefined;
    s.bytes(&nonce);

    const token_str = try key.encrypt(allocator, message, .{
        .footer = footer,
        .implicit_assertion = assertion,
        .nonce = nonce,
    });
    defer allocator.free(token_str);

    const recovered = try key.decrypt(allocator, token_str, assertion);
    defer allocator.free(recovered);
    try std.testing.expectEqualSlices(u8, message, recovered);
}

fn mutationFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var key_buf: [32]u8 = undefined;
    s.bytes(&key_buf);
    const key = try paseto.v3.Local.fromBytes(&key_buf);

    var msg_buf: [256]u8 = undefined;
    const msg_n = s.slice(&msg_buf);
    const message = msg_buf[0..msg_n];
    var footer_buf: [64]u8 = undefined;
    const f_n = s.slice(&footer_buf);
    const footer = footer_buf[0..f_n];
    var assertion_buf: [64]u8 = undefined;
    const a_n = s.slice(&assertion_buf);
    const assertion = assertion_buf[0..a_n];
    var nonce: [32]u8 = undefined;
    s.bytes(&nonce);

    const token_str = try key.encrypt(allocator, message, .{
        .footer = footer,
        .implicit_assertion = assertion,
        .nonce = nonce,
    });
    defer allocator.free(token_str);

    for (support.token_mutation_classes) |mutation| {
        const tampered = try support.mutateToken(allocator, token_str, mutation, s);
        defer allocator.free(tampered);

        if (std.mem.eql(u8, tampered, token_str)) continue;

        if (key.decrypt(allocator, tampered, assertion)) |ok| {
            allocator.free(ok);
            return error.MutatedTokenShouldNotDecrypt;
        } else |err| {
            try support.expectAllowed(err, &support.local_decrypt_errors);
        }
    }
}

fn wrongKeyFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var key_buf: [32]u8 = undefined;
    s.bytes(&key_buf);
    const key = try paseto.v3.Local.fromBytes(&key_buf);

    var wrong_key_buf = key_buf;
    const wrong_idx = s.valueRangeLessThan(u64, 0, wrong_key_buf.len);
    wrong_key_buf[@intCast(wrong_idx)] ^= 0xff;
    const wrong_key = try paseto.v3.Local.fromBytes(&wrong_key_buf);

    var msg_buf: [256]u8 = undefined;
    const msg_n = s.slice(&msg_buf);
    const message = msg_buf[0..msg_n];
    var footer_buf: [64]u8 = undefined;
    const f_n = s.slice(&footer_buf);
    const footer = footer_buf[0..f_n];
    var assertion_buf: [64]u8 = undefined;
    const a_n = s.slice(&assertion_buf);
    const assertion = assertion_buf[0..a_n];
    var nonce: [32]u8 = undefined;
    s.bytes(&nonce);

    const token_str = try key.encrypt(allocator, message, .{
        .footer = footer,
        .implicit_assertion = assertion,
        .nonce = nonce,
    });
    defer allocator.free(token_str);

    if (wrong_key.decrypt(allocator, token_str, assertion)) |ok| {
        allocator.free(ok);
        return error.WrongKeyShouldNotDecrypt;
    } else |err| {
        try support.expectAllowed(err, &support.local_decrypt_errors);
    }
}
