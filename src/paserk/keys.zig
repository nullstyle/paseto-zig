//! Byte-level PASERK serialization for key types. Parser paths validate key
//! material where the stdlib exposes checks for the corresponding primitive.

const std = @import("std");
const util = @import("../util.zig");
const errors = @import("../errors.zig");
const token_mod = @import("../token.zig");

pub const Error = errors.Error;
pub const Version = token_mod.Version;

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const P384 = std.crypto.ecc.P384;

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
    try validateKeyMaterial(version, kind, key_bytes);
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
        util.secureFree(self.allocator, self.bytes);
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
        util.secureFree(self.allocator, self.bytes);
        self.* = undefined;
    }
};

pub fn parse(allocator: std.mem.Allocator, paserk: []const u8) !Decoded {
    if (paserk.len > util.max_paserk_string_bytes) return Error.InvalidEncoding;

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

    if (data_s.len != util.encodedBase64Len(keyLen(version, kind))) return Error.InvalidKey;

    const bytes = try util.decodeBase64Alloc(allocator, data_s);
    errdefer util.secureFree(allocator, bytes);
    try validateKeyLength(version, kind, bytes.len);
    try validateKeyMaterial(version, kind, bytes);
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

fn keyLen(version: Version, kind: KeyType) usize {
    return switch (version) {
        .v3 => switch (kind) {
            .local => 32,
            .public => 49,
            .secret => 48,
        },
        .v4 => switch (kind) {
            .local => 32,
            .public => 32,
            .secret => 64,
        },
    };
}

pub fn validateKeyMaterial(version: Version, kind: KeyType, bytes: []const u8) !void {
    switch (version) {
        .v3 => switch (kind) {
            .local => {},
            .public => _ = P384.fromSec1(bytes) catch return Error.InvalidKey,
            .secret => _ = EcdsaP384Sha384.KeyPair.fromSecretKey(.{ .bytes = bytes[0..48].* }) catch
                return Error.InvalidKey,
        },
        .v4 => switch (kind) {
            .local => {},
            .public => _ = Ed25519.PublicKey.fromBytes(bytes[0..32].*) catch return Error.InvalidKey,
            .secret => {
                const sk_bytes = bytes[0..64].*;
                const sk = Ed25519.SecretKey.fromBytes(sk_bytes) catch return Error.InvalidKey;
                const kp = Ed25519.KeyPair.fromSecretKey(sk) catch return Error.InvalidKey;
                const derived = Ed25519.KeyPair.generateDeterministic(sk.seed()) catch return Error.InvalidKey;
                if (!std.mem.eql(u8, &derived.public_key.toBytes(), &kp.public_key.toBytes())) {
                    return Error.InvalidKeyPair;
                }
            },
        },
    }
}
