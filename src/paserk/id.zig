//! PASERK ID operations: `lid`, `sid`, `pid`. IDs are the truncated hash of
//! a PASERK string — 33 bytes, base64url-encoded.

const std = @import("std");
const util = @import("../util.zig");
const errors = @import("../errors.zig");
const keys = @import("keys.zig");
const token_mod = @import("../token.zig");

pub const Error = errors.Error;
pub const Version = token_mod.Version;

const Blake2b = std.crypto.hash.blake2.Blake2b;
const Sha384 = std.crypto.hash.sha2.Sha384;

const id_digest_bytes = 33;

pub const IdKind = enum {
    lid,
    sid,
    pid,

    fn label(self: IdKind) []const u8 {
        return switch (self) {
            .lid => "lid",
            .sid => "sid",
            .pid => "pid",
        };
    }

    fn sourceKind(self: IdKind) keys.KeyType {
        return switch (self) {
            .lid => .local,
            .sid => .secret,
            .pid => .public,
        };
    }
};

/// Compute a PASERK ID from raw key material.
pub fn compute(
    allocator: std.mem.Allocator,
    version: Version,
    kind: IdKind,
    key_bytes: []const u8,
) ![]u8 {
    const src_paserk = try keys.serialize(allocator, version, kind.sourceKind(), key_bytes);
    defer allocator.free(src_paserk);

    const prefix = version.paserkPrefix();
    const label = kind.label();
    // Header string: "{k3|k4}.{lid|sid|pid}."
    var header_buf: [16]u8 = undefined;
    std.debug.assert(prefix.len + 1 + label.len + 1 <= header_buf.len);
    var idx: usize = 0;
    @memcpy(header_buf[idx..][0..prefix.len], prefix);
    idx += prefix.len;
    header_buf[idx] = '.';
    idx += 1;
    @memcpy(header_buf[idx..][0..label.len], label);
    idx += label.len;
    header_buf[idx] = '.';
    idx += 1;
    const header = header_buf[0..idx];

    var digest: [id_digest_bytes]u8 = undefined;
    switch (version) {
        .v3 => {
            var full: [Sha384.digest_length]u8 = undefined;
            var h = Sha384.init(.{});
            h.update(header);
            h.update(src_paserk);
            h.final(&full);
            @memcpy(&digest, full[0..id_digest_bytes]);
        },
        .v4 => {
            var h = Blake2b(id_digest_bytes * 8).init(.{});
            h.update(header);
            h.update(src_paserk);
            h.final(&digest);
        },
    }

    const encoded_len = util.encodedBase64Len(id_digest_bytes);
    const out = try allocator.alloc(u8, header.len + encoded_len);
    errdefer allocator.free(out);
    @memcpy(out[0..header.len], header);
    _ = util.encodeBase64(out[header.len..][0..encoded_len], &digest);
    return out;
}

pub fn lid(
    allocator: std.mem.Allocator,
    version: Version,
    local_key_bytes: []const u8,
) ![]u8 {
    return try compute(allocator, version, .lid, local_key_bytes);
}

pub fn sid(
    allocator: std.mem.Allocator,
    version: Version,
    secret_key_bytes: []const u8,
) ![]u8 {
    return try compute(allocator, version, .sid, secret_key_bytes);
}

pub fn pid(
    allocator: std.mem.Allocator,
    version: Version,
    public_key_bytes: []const u8,
) ![]u8 {
    return try compute(allocator, version, .pid, public_key_bytes);
}
