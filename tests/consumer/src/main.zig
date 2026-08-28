const std = @import("std");
const paseto = @import("paseto");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const key = paseto.v4.Local.generate();
    const token = try key.encrypt(allocator, "{\"sub\":\"alice\"}", .{
        .footer = "{\"kid\":\"demo\"}",
        .implicit_assertion = "consumer-smoke",
    });
    defer allocator.free(token);

    var result = try key.decryptWithFooter(allocator, token, "consumer-smoke");
    defer result.deinit();
    if (!std.mem.eql(u8, result.claims_bytes, "{\"sub\":\"alice\"}")) return error.SmokeFailed;
    if (!std.mem.eql(u8, result.footer, "{\"kid\":\"demo\"}")) return error.SmokeFailed;

    const paserk = try key.paserkLocal(allocator);
    defer allocator.free(paserk);
    const parsed_key = try paseto.v4.Local.fromPaserk(allocator, paserk);
    if (!key.eql(parsed_key)) return error.SmokeFailed;
}
