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

pub const digest_bytes = 33;
pub const encoded_digest_bytes = encodedBase64LenComptime(digest_bytes);
pub const string_bytes = "k3.lid.".len + encoded_digest_bytes;

const max_key_material_bytes = 64;
const max_key_encoded_bytes = encodedBase64LenComptime(max_key_material_bytes);

pub const IdKind = enum {
    lid,
    sid,
    pid,

    pub fn label(self: IdKind) []const u8 {
        return switch (self) {
            .lid => "lid",
            .sid => "sid",
            .pid => "pid",
        };
    }

    pub fn fromLabel(name: []const u8) ?IdKind {
        if (std.mem.eql(u8, name, "lid")) return .lid;
        if (std.mem.eql(u8, name, "sid")) return .sid;
        if (std.mem.eql(u8, name, "pid")) return .pid;
        return null;
    }

    pub fn sourceKind(self: IdKind) keys.KeyType {
        return switch (self) {
            .lid => .local,
            .sid => .secret,
            .pid => .public,
        };
    }
};

/// Parsed PASERK ID handle.
///
/// This is a non-owning, fixed-size value type. It stores the decoded 33-byte
/// ID digest together with the PASERK version and ID kind, so callers can pass
/// IDs around without treating them as unstructured strings. Use `toString`
/// or `write` when canonical PASERK text is needed.
pub const Id = struct {
    version: Version,
    kind: IdKind,
    digest: [digest_bytes]u8,

    pub fn fromKey(
        version: Version,
        kind: IdKind,
        key_bytes: []const u8,
    ) !Id {
        return .{
            .version = version,
            .kind = kind,
            .digest = try computeDigest(version, kind, key_bytes),
        };
    }

    pub fn parse(paserk_id: []const u8) !Id {
        var parts_it = std.mem.splitScalar(u8, paserk_id, '.');
        const version_s = parts_it.next() orelse return Error.InvalidKeyId;
        const kind_s = parts_it.next() orelse return Error.InvalidKeyId;
        const digest_s = parts_it.next() orelse return Error.InvalidKeyId;
        if (parts_it.next() != null) return Error.InvalidKeyId;

        const version = Version.fromPaserkPrefix(version_s) orelse return Error.UnsupportedVersion;
        const kind = IdKind.fromLabel(kind_s) orelse return Error.UnsupportedOperation;
        if (digest_s.len != encoded_digest_bytes) return Error.InvalidKeyId;

        var digest: [digest_bytes]u8 = undefined;
        util.decodeBase64(&digest, digest_s) catch |err| switch (err) {
            Error.InvalidEncoding => return Error.InvalidKeyId,
            else => return err,
        };

        return .{
            .version = version,
            .kind = kind,
            .digest = digest,
        };
    }

    pub fn header(self: Id) []const u8 {
        return headerFor(self.version, self.kind);
    }

    pub fn eql(self: Id, other: Id) bool {
        return self.version == other.version and
            self.kind == other.kind and
            util.constantTimeEqual(&self.digest, &other.digest);
    }

    pub fn eqlString(self: Id, paserk_id: []const u8) bool {
        const parsed = Id.parse(paserk_id) catch return false;
        return self.eql(parsed);
    }

    pub fn toArray(self: Id) [string_bytes]u8 {
        var out: [string_bytes]u8 = undefined;
        const header_s = self.header();
        @memcpy(out[0..header_s.len], header_s);
        _ = util.encodeBase64(out[header_s.len..][0..encoded_digest_bytes], &self.digest);
        return out;
    }

    pub fn write(self: Id, out: []u8) error{NoSpaceLeft}![]const u8 {
        if (out.len < string_bytes) return error.NoSpaceLeft;
        const encoded = self.toArray();
        @memcpy(out[0..string_bytes], &encoded);
        return out[0..string_bytes];
    }

    pub fn toString(self: Id, allocator: std.mem.Allocator) ![]u8 {
        const out = try allocator.alloc(u8, string_bytes);
        errdefer allocator.free(out);
        _ = self.write(out) catch unreachable;
        return out;
    }

    pub fn format(self: Id, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const encoded = self.toArray();
        try writer.writeAll(&encoded);
    }
};

/// Compute a PASERK ID from raw key material.
pub fn compute(
    version: Version,
    kind: IdKind,
    key_bytes: []const u8,
) !Id {
    return try Id.fromKey(version, kind, key_bytes);
}

pub fn lid(
    version: Version,
    local_key_bytes: []const u8,
) !Id {
    return try compute(version, .lid, local_key_bytes);
}

pub fn sid(
    version: Version,
    secret_key_bytes: []const u8,
) !Id {
    return try compute(version, .sid, secret_key_bytes);
}

pub fn pid(
    version: Version,
    public_key_bytes: []const u8,
) !Id {
    return try compute(version, .pid, public_key_bytes);
}

pub fn parse(paserk_id: []const u8) !Id {
    return try Id.parse(paserk_id);
}

fn computeDigest(version: Version, kind: IdKind, key_bytes: []const u8) ![digest_bytes]u8 {
    try keys.validateKeyLength(version, kind.sourceKind(), key_bytes.len);

    const id_header = headerFor(version, kind);
    const key_header = sourceHeaderFor(version, kind.sourceKind());
    var encoded_key_buf: [max_key_encoded_bytes]u8 = undefined;
    const encoded_key_len = util.encodedBase64Len(key_bytes.len);
    std.debug.assert(encoded_key_len <= encoded_key_buf.len);
    const encoded_key = util.encodeBase64(encoded_key_buf[0..encoded_key_len], key_bytes);

    var digest: [digest_bytes]u8 = undefined;
    switch (version) {
        .v3 => {
            var full: [Sha384.digest_length]u8 = undefined;
            var h = Sha384.init(.{});
            h.update(id_header);
            h.update(key_header);
            h.update(encoded_key);
            h.final(&full);
            @memcpy(&digest, full[0..digest_bytes]);
        },
        .v4 => {
            var h = Blake2b(digest_bytes * 8).init(.{});
            h.update(id_header);
            h.update(key_header);
            h.update(encoded_key);
            h.final(&digest);
        },
    }
    return digest;
}

fn headerFor(version: Version, kind: IdKind) []const u8 {
    return switch (version) {
        .v3 => switch (kind) {
            .lid => "k3.lid.",
            .sid => "k3.sid.",
            .pid => "k3.pid.",
        },
        .v4 => switch (kind) {
            .lid => "k4.lid.",
            .sid => "k4.sid.",
            .pid => "k4.pid.",
        },
    };
}

fn sourceHeaderFor(version: Version, kind: keys.KeyType) []const u8 {
    return switch (version) {
        .v3 => switch (kind) {
            .local => "k3.local.",
            .secret => "k3.secret.",
            .public => "k3.public.",
        },
        .v4 => switch (kind) {
            .local => "k4.local.",
            .secret => "k4.secret.",
            .public => "k4.public.",
        },
    };
}

fn encodedBase64LenComptime(comptime raw_len: usize) comptime_int {
    return (raw_len * 4 + 2) / 3;
}

test "Id computes, parses, serializes, and compares" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = @splat(0);

    const id_handle = try Id.fromKey(.v4, .lid, &key);
    const encoded = try id_handle.toString(allocator);
    defer allocator.free(encoded);

    try std.testing.expect(std.mem.startsWith(u8, encoded, "k4.lid."));
    try std.testing.expectEqual(@as(usize, string_bytes), encoded.len);

    const parsed = try Id.parse(encoded);
    try std.testing.expect(id_handle.eql(parsed));
    try std.testing.expect(id_handle.eqlString(encoded));

    var buf: [string_bytes]u8 = undefined;
    const written = try id_handle.write(&buf);
    try std.testing.expectEqualSlices(u8, encoded, written);
    try std.testing.expectError(error.NoSpaceLeft, id_handle.write(buf[0 .. string_bytes - 1]));

    const formatted = try std.fmt.allocPrint(allocator, "{f}", .{id_handle});
    defer allocator.free(formatted);
    try std.testing.expectEqualSlices(u8, encoded, formatted);
}

test "Id parse rejects malformed ids" {
    try std.testing.expectError(Error.InvalidKeyId, Id.parse("k4.lid"));
    try std.testing.expectError(Error.InvalidKeyId, Id.parse("k4.lid.too.short"));
    try std.testing.expectError(Error.UnsupportedVersion, Id.parse("k2.lid.bqltbNc4JLUAmc9Xtpok-fBuI0dQN5_m3CD9W_nbh559"));
    try std.testing.expectError(Error.UnsupportedOperation, Id.parse("k4.xid.bqltbNc4JLUAmc9Xtpok-fBuI0dQN5_m3CD9W_nbh559"));
    try std.testing.expectError(Error.InvalidBase64, Id.parse("k4.lid.********************************************"));
}
