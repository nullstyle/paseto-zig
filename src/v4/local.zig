const std = @import("std");
const util = @import("../util.zig");
const errors = @import("../errors.zig");
const token_mod = @import("../token.zig");
const keys_mod = @import("../paserk/keys.zig");
const id_mod = @import("../paserk/id.zig");
const pie_mod = @import("../paserk/pie.zig");
const pbkw_mod = @import("../paserk/pbkw.zig");

pub const Error = errors.Error;

const Blake2b = std.crypto.hash.blake2.Blake2b;

pub const key_bytes = 32;
pub const nonce_bytes = 32; // Random nonce put on the wire.
pub const xnonce_bytes = 24; // Derived XChaCha20 nonce.
pub const mac_bytes = 32;

const pae_header = "v4.local.";

/// A PASETO v4.local symmetric key (256-bit raw IKM).
pub const Local = struct {
    key: [key_bytes]u8,

    pub fn fromBytes(bytes: []const u8) !Local {
        if (bytes.len != key_bytes) return Error.InvalidKey;
        var k: Local = .{ .key = undefined };
        @memcpy(&k.key, bytes);
        return k;
    }

    pub fn generate() Local {
        var k: Local = .{ .key = undefined };
        util.randomBytes(&k.key);
        return k;
    }

    pub fn eql(self: Local, other: Local) bool {
        return util.constantTimeEqual(&self.key, &other.key);
    }

    pub const Options = struct {
        footer: []const u8 = "",
        implicit_assertion: []const u8 = "",
        /// Used to inject a deterministic nonce in test vectors. Production
        /// callers should leave this null.
        nonce: ?[nonce_bytes]u8 = null,
    };

    /// Encrypt `message` to a PASETO token string. Caller owns the returned
    /// buffer.
    pub fn encrypt(
        self: Local,
        allocator: std.mem.Allocator,
        message: []const u8,
        opts: Options,
    ) ![]u8 {
        var nonce: [nonce_bytes]u8 = undefined;
        if (opts.nonce) |n| {
            @memcpy(&nonce, &n);
        } else {
            util.randomBytes(&nonce);
        }

        const keys = deriveKeys(self.key, nonce);

        const ciphertext = try allocator.alloc(u8, message.len);
        defer allocator.free(ciphertext);
        std.crypto.stream.chacha.XChaCha20IETF.xor(ciphertext, message, 0, keys.ek, keys.n2);

        // PAE over header, nonce, ciphertext, footer, implicit assertion.
        var pae_parts: [5][]const u8 = .{
            pae_header,
            &nonce,
            ciphertext,
            opts.footer,
            opts.implicit_assertion,
        };
        const pae = try util.preAuthEncodeAlloc(allocator, &pae_parts);
        defer allocator.free(pae);

        var tag: [mac_bytes]u8 = undefined;
        Blake2b(mac_bytes * 8).hash(pae, &tag, .{ .key = &keys.ak });

        // Payload = nonce || ciphertext || tag
        const raw_payload = try allocator.alloc(u8, nonce_bytes + ciphertext.len + mac_bytes);
        defer allocator.free(raw_payload);
        @memcpy(raw_payload[0..nonce_bytes], &nonce);
        @memcpy(raw_payload[nonce_bytes .. nonce_bytes + ciphertext.len], ciphertext);
        @memcpy(raw_payload[nonce_bytes + ciphertext.len ..], &tag);

        return try token_mod.serialize(allocator, .v4, .local, raw_payload, opts.footer);
    }

    /// Decrypt a PASETO token string, returning the plaintext message.
    /// Caller owns the returned buffer.
    pub fn decrypt(
        self: Local,
        allocator: std.mem.Allocator,
        token_str: []const u8,
        implicit_assertion: []const u8,
    ) ![]u8 {
        var tok = try token_mod.parse(allocator, token_str);
        defer tok.deinit();
        return try self.decryptToken(allocator, tok, implicit_assertion);
    }

    /// Decrypt using an already-parsed Token. The token is borrowed for the
    /// duration of the call and is not modified.
    pub fn decryptToken(
        self: Local,
        allocator: std.mem.Allocator,
        tok: token_mod.Token,
        implicit_assertion: []const u8,
    ) ![]u8 {
        if (tok.version != .v4 or tok.purpose != .local) return Error.WrongPurpose;
        const payload = tok.payload;
        if (payload.len < nonce_bytes + mac_bytes) return Error.MessageTooShort;

        const nonce = payload[0..nonce_bytes];
        const ciphertext = payload[nonce_bytes .. payload.len - mac_bytes];
        const tag = payload[payload.len - mac_bytes ..];

        const keys = deriveKeys(self.key, nonce.*);

        var pae_parts: [5][]const u8 = .{
            pae_header,
            nonce,
            ciphertext,
            tok.footer,
            implicit_assertion,
        };
        const pae = try util.preAuthEncodeAlloc(allocator, &pae_parts);
        defer allocator.free(pae);

        var expected_tag: [mac_bytes]u8 = undefined;
        Blake2b(mac_bytes * 8).hash(pae, &expected_tag, .{ .key = &keys.ak });

        if (!util.constantTimeEqual(tag, &expected_tag)) return Error.InvalidAuthenticator;

        const plaintext = try allocator.alloc(u8, ciphertext.len);
        errdefer allocator.free(plaintext);
        std.crypto.stream.chacha.XChaCha20IETF.xor(plaintext, ciphertext, 0, keys.ek, keys.n2);
        return plaintext;
    }

    /// Serialize the key as a `k4.local.` PASERK string.
    pub fn paserkLocal(self: Local, allocator: std.mem.Allocator) ![]u8 {
        return try keys_mod.serialize(allocator, .v4, .local, &self.key);
    }

    /// Compute the `k4.lid.` PASERK ID for this key.
    pub fn lid(self: Local) !id_mod.Id {
        return try id_mod.lid(.v4, &self.key);
    }

    /// Wrap another v4.local key using this key as the symmetric wrapping
    /// key (PIE construction). Returns a `k4.local-wrap.pie.` PASERK.
    pub fn wrapLocal(
        self: Local,
        allocator: std.mem.Allocator,
        other: Local,
        opts: pie_mod.WrapOptions,
    ) ![]u8 {
        return try pie_mod.wrap(allocator, .v4, .local, &self.key, &other.key, opts);
    }

    /// Wrap a v4 Ed25519 secret key using this key. Returns a
    /// `k4.secret-wrap.pie.` PASERK.
    pub fn wrapSecret(
        self: Local,
        allocator: std.mem.Allocator,
        secret_bytes: []const u8,
        opts: pie_mod.WrapOptions,
    ) ![]u8 {
        return try pie_mod.wrap(allocator, .v4, .secret, &self.key, secret_bytes, opts);
    }

    /// Unwrap a `k4.local-wrap.pie.` or `k4.secret-wrap.pie.` PASERK.
    pub fn unwrap(
        self: Local,
        allocator: std.mem.Allocator,
        paserk: []const u8,
    ) !pie_mod.Unwrapped {
        return try pie_mod.unwrap(allocator, &self.key, paserk);
    }

    /// Encrypt this key with a password, yielding a `k4.local-pw.` PASERK.
    pub fn wrapWithPassword(
        self: Local,
        allocator: std.mem.Allocator,
        password: []const u8,
        opts: pbkw_mod.WrapOptionsV4,
    ) ![]u8 {
        return try pbkw_mod.wrapV4(allocator, .local, password, &self.key, opts);
    }
};

const DerivedKeys = struct {
    ek: [32]u8,
    n2: [xnonce_bytes]u8,
    ak: [32]u8,
};

fn deriveKeys(key: [key_bytes]u8, nonce: [nonce_bytes]u8) DerivedKeys {
    var tmp: [56]u8 = undefined;
    var out: DerivedKeys = undefined;

    // tmp = BLAKE2b-56(key=key, data="paseto-encryption-key"||nonce)
    var h = Blake2b(56 * 8).init(.{ .key = &key });
    h.update("paseto-encryption-key");
    h.update(&nonce);
    h.final(&tmp);

    @memcpy(&out.ek, tmp[0..32]);
    @memcpy(&out.n2, tmp[32..56]);

    // ak = BLAKE2b-32(key=key, data="paseto-auth-key-for-aead"||nonce)
    var h2 = Blake2b(32 * 8).init(.{ .key = &key });
    h2.update("paseto-auth-key-for-aead");
    h2.update(&nonce);
    h2.final(&out.ak);

    return out;
}

test "v4.local encrypt decrypt round trip" {
    const allocator = std.testing.allocator;
    const key = Local.generate();
    const token_str = try key.encrypt(allocator, "hello paseto", .{ .footer = "tail" });
    defer allocator.free(token_str);
    const plaintext = try key.decrypt(allocator, token_str, "");
    defer allocator.free(plaintext);
    try std.testing.expectEqualSlices(u8, "hello paseto", plaintext);
}
