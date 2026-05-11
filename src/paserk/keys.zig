//! Byte-level PASERK serialization for key types. Operates on raw key
//! material without validating point-on-curve semantics; callers performing
//! cryptographic operations use the parsed key types in `v3`/`v4`.

const std = @import("std");
const util = @import("../util.zig");
const errors = @import("../errors.zig");
const token_mod = @import("../token.zig");

pub const Error = errors.Error;
pub const Version = token_mod.Version;

pub const KeyType = enum {
    local,
    public,
    secret,

    pub fn headerName(self: KeyType) []const u8 {
        return switch (self) {
            .local => "local",
            .public => "public",
            .secret => "secret",
        };
    }
};

pub fn serialize(
    allocator: std.mem.Allocator,
    version: Version,
    kind: KeyType,
    key_bytes: []const u8,
) ![]u8 {
    try validateKeyLength(version, kind, key_bytes.len);
    return try writeKeyPaserk(allocator, version, kind, key_bytes);
}

fn writeKeyPaserk(
    allocator: std.mem.Allocator,
    version: Version,
    kind: KeyType,
    key_bytes: []const u8,
) ![]u8 {
    const prefix = version.paserkPrefix();
    const kind_name = kind.headerName();
    const encoded_len = util.encodedBase64Len(key_bytes.len);
    // format: "{k3|k4}.{local|public|secret}.<base64url>"
    const out_len = prefix.len + 1 + kind_name.len + 1 + encoded_len;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);
    var idx: usize = 0;
    @memcpy(out[idx..][0..prefix.len], prefix);
    idx += prefix.len;
    out[idx] = '.';
    idx += 1;
    @memcpy(out[idx..][0..kind_name.len], kind_name);
    idx += kind_name.len;
    out[idx] = '.';
    idx += 1;
    _ = util.encodeBase64(out[idx..][0..encoded_len], key_bytes);
    return out;
}

/// Decoded PASERK carrying its version/type and raw bytes.
///
/// Ownership model:
/// * Call `deinit` exactly once when done.
/// * Do not copy the struct by value and keep both copies alive across
///   `deinit`; both copies would share the same heap allocation.
pub const Decoded = struct {
    version: Version,
    kind: KeyType,
    bytes: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Decoded) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// Subset of `KeyType` that covers what a wrapping operation can produce.
/// Used by both PIE (`local-wrap` / `secret-wrap`) and PBKW (`local-pw` /
/// `secret-pw`), which never emit a bare public key.
pub const WrappedKind = enum {
    local,
    secret,

    pub fn toKeyType(self: WrappedKind) KeyType {
        return switch (self) {
            .local => .local,
            .secret => .secret,
        };
    }
};

/// Output of a PASERK wrap/unwrap operation. Used by both `pie` and `pbkw`.
///
/// Ownership model:
/// * Call `deinit` exactly once when done.
/// * Do not copy the struct by value and keep both copies alive across
///   `deinit`; both copies would share the same heap allocation.
pub const UnwrappedKey = struct {
    version: Version,
    kind: WrappedKind,
    bytes: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *UnwrappedKey) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub fn parse(allocator: std.mem.Allocator, paserk: []const u8) !Decoded {
    var parts_it = std.mem.splitScalar(u8, paserk, '.');
    const version_s = parts_it.next() orelse return Error.InvalidEncoding;
    const kind_s = parts_it.next() orelse return Error.InvalidEncoding;
    const data_s = parts_it.next() orelse return Error.InvalidEncoding;
    if (parts_it.next() != null) return Error.InvalidEncoding;

    const version = Version.fromPaserkPrefix(version_s) orelse return Error.UnsupportedVersion;
    const kind: KeyType = if (std.mem.eql(u8, kind_s, "local"))
        .local
    else if (std.mem.eql(u8, kind_s, "public"))
        .public
    else if (std.mem.eql(u8, kind_s, "secret"))
        .secret
    else
        return Error.UnsupportedOperation;

    const bytes = try util.decodeBase64Alloc(allocator, data_s);
    errdefer allocator.free(bytes);
    try validateKeyLength(version, kind, bytes.len);
    return .{
        .version = version,
        .kind = kind,
        .bytes = bytes,
        .allocator = allocator,
    };
}

/// Validate raw PASERK key material length for the given version and key type.
pub fn validateKeyLength(version: Version, kind: KeyType, len: usize) !void {
    switch (version) {
        .v3 => switch (kind) {
            .local => if (len != 32) return Error.InvalidKey,
            .public => if (len != 49) return Error.InvalidKey, // compressed SEC1
            .secret => if (len != 48) return Error.InvalidKey, // raw scalar
        },
        .v4 => switch (kind) {
            .local => if (len != 32) return Error.InvalidKey,
            .public => if (len != 32) return Error.InvalidKey,
            .secret => if (len != 64) return Error.InvalidKey, // seed || pubkey
        },
    }
}
