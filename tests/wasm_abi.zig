const std = @import("std");
const wasm = @import("paseto_wasm");

test "WASM ABI constants are stable" {
    try std.testing.expectEqual(@as(u32, 1), wasm.abi_version);
    try std.testing.expectEqual(@as(usize, 8), wasm.result_descriptor_bytes);
    try std.testing.expectEqual(@as(usize, 8), wasm.open_result_header_bytes);
    try std.testing.expectEqual(@as(usize, 51), wasm.local_key_id_bytes);
}

test "WASM ABI seals and opens message plus authenticated footer" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = @splat(0x42);
    const nonce: [32]u8 = @splat(0x24);
    const message = "{\"sub\":\"alice\",\"jti\":\"session-1\"}";
    const footer = "{\"kid\":\"primary\"}";
    const implicit_assertion = "issuer.example|audience.example";

    const seal_input = try makeSealFrame(allocator, &key, &nonce, message, footer, implicit_assertion);
    defer allocator.free(seal_input);
    var sealed = wasm.test_api.seal(allocator, seal_input);
    defer sealed.deinit();
    try std.testing.expectEqual(wasm.Status.ok, sealed.status);
    const token = sealed.output.?;
    try std.testing.expect(std.mem.startsWith(u8, token, "v4.local."));

    const open_input = try makeOpenFrame(allocator, &key, token, implicit_assertion);
    defer allocator.free(open_input);
    var opened = wasm.test_api.open(allocator, open_input);
    defer opened.deinit();
    try std.testing.expectEqual(wasm.Status.ok, opened.status);

    const output = opened.output.?;
    const message_len = std.mem.readInt(u32, output[0..4], .little);
    const footer_len = std.mem.readInt(u32, output[4..8], .little);
    try std.testing.expectEqual(@as(u32, message.len), message_len);
    try std.testing.expectEqual(@as(u32, footer.len), footer_len);
    try std.testing.expectEqualSlices(u8, message, output[8..][0..message_len]);
    try std.testing.expectEqualSlices(u8, footer, output[8 + message_len ..]);
}

test "WASM ABI rejects tampering and malformed frames with distinct statuses" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = @splat(7);
    const nonce: [32]u8 = @splat(9);

    const seal_input = try makeSealFrame(allocator, &key, &nonce, "payload", "footer", "assertion");
    defer allocator.free(seal_input);
    var sealed = wasm.test_api.seal(allocator, seal_input);
    defer sealed.deinit();
    try std.testing.expectEqual(wasm.Status.ok, sealed.status);

    const wrong_assertion = try makeOpenFrame(allocator, &key, sealed.output.?, "different");
    defer allocator.free(wrong_assertion);
    var rejected = wasm.test_api.open(allocator, wrong_assertion);
    defer rejected.deinit();
    try std.testing.expectEqual(wasm.Status.crypto_error, rejected.status);
    try std.testing.expectEqual(@as(?[]u8, null), rejected.output);

    const truncated = seal_input[0 .. seal_input.len - 1];
    var malformed = wasm.test_api.seal(allocator, truncated);
    defer malformed.deinit();
    try std.testing.expectEqual(wasm.Status.invalid_input, malformed.status);
    try std.testing.expectEqual(@as(?[]u8, null), malformed.output);

    const empty_open = try makeOpenFrame(allocator, &key, "", "");
    defer allocator.free(empty_open);
    var empty = wasm.test_api.open(allocator, empty_open);
    defer empty.deinit();
    try std.testing.expectEqual(wasm.Status.invalid_input, empty.status);
}

test "WASM ABI emits the canonical v4.local PASERK ID" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = @splat(0);

    var invocation = wasm.test_api.localKeyId(allocator, &key);
    defer invocation.deinit();
    try std.testing.expectEqual(wasm.Status.ok, invocation.status);
    try std.testing.expectEqualSlices(
        u8,
        "k4.lid.bqltbNc4JLUAmc9Xtpok-fBuI0dQN5_m3CD9W_nbh559",
        invocation.output.?,
    );

    var short = wasm.test_api.localKeyId(allocator, key[0..31]);
    defer short.deinit();
    try std.testing.expectEqual(wasm.Status.invalid_input, short.status);
}

test "WASM ABI reset wipes and reclaims the arena high-water range" {
    wasm.test_api.resetArena();
    const bytes = try wasm.test_api.arenaAllocate(4096);
    @memset(bytes, 0xa5);
    try std.testing.expect(wasm.test_api.arenaNonZeroBytes() >= bytes.len);

    wasm.test_api.resetArena();
    try std.testing.expectEqual(@as(usize, 0), wasm.test_api.arenaNonZeroBytes());

    const reused = try wasm.test_api.arenaAllocate(4096);
    try std.testing.expectEqual(@as(usize, 4096), reused.len);
    wasm.test_api.resetArena();
}

fn makeSealFrame(
    allocator: std.mem.Allocator,
    key: *const [32]u8,
    nonce: *const [32]u8,
    message: []const u8,
    footer: []const u8,
    implicit_assertion: []const u8,
) ![]u8 {
    const header_len = 32 + 32 + 12;
    const output = try allocator.alloc(u8, header_len + message.len + footer.len + implicit_assertion.len);
    @memcpy(output[0..32], key);
    @memcpy(output[32..64], nonce);
    std.mem.writeInt(u32, output[64..68], @intCast(message.len), .little);
    std.mem.writeInt(u32, output[68..72], @intCast(footer.len), .little);
    std.mem.writeInt(u32, output[72..76], @intCast(implicit_assertion.len), .little);
    var offset: usize = header_len;
    @memcpy(output[offset..][0..message.len], message);
    offset += message.len;
    @memcpy(output[offset..][0..footer.len], footer);
    offset += footer.len;
    @memcpy(output[offset..], implicit_assertion);
    return output;
}

fn makeOpenFrame(
    allocator: std.mem.Allocator,
    key: *const [32]u8,
    token: []const u8,
    implicit_assertion: []const u8,
) ![]u8 {
    const header_len = 32 + 8;
    const output = try allocator.alloc(u8, header_len + token.len + implicit_assertion.len);
    @memcpy(output[0..32], key);
    std.mem.writeInt(u32, output[32..36], @intCast(token.len), .little);
    std.mem.writeInt(u32, output[36..40], @intCast(implicit_assertion.len), .little);
    @memcpy(output[40..][0..token.len], token);
    @memcpy(output[40 + token.len ..], implicit_assertion);
    return output;
}
