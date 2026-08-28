const std = @import("std");
const util = @import("../util.zig");
const errors = @import("../errors.zig");
const token_mod = @import("../token.zig");
const claims_mod = @import("../claims.zig");
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

    pub fn fromPaserk(allocator: std.mem.Allocator, paserk: []const u8) !Local {
        var decoded = try keys_mod.parse(allocator, paserk);
        defer decoded.deinit();
        if (decoded.version != .v4) return Error.WrongVersion;
        if (decoded.kind != .local) return Error.WrongPurpose;
        return try fromBytes(decoded.bytes);
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

        return try self.encryptWithNonce(
            allocator,
            message,
            &nonce,
            opts.footer,
            opts.implicit_assertion,
        );
    }

    /// Encrypt with a caller-supplied 32-byte nonce. This is the freestanding
    /// primitive used by the WASM ABI, where the host supplies CSPRNG bytes.
    /// Reusing a nonce with the same key breaks confidentiality.
    pub fn encryptWithNonce(
        self: *const Local,
        allocator: std.mem.Allocator,
        message: []const u8,
        nonce: *const [nonce_bytes]u8,
        footer: []const u8,
        implicit_assertion: []const u8,
    ) ![]u8 {
        var keys = deriveKeys(&self.key, nonce);
        defer util.secureZero(std.mem.asBytes(&keys));

        const ciphertext = try allocator.alloc(u8, message.len);
        defer util.secureFree(allocator, ciphertext);
        std.crypto.stream.chacha.XChaCha20IETF.xor(ciphertext, message, 0, keys.ek, keys.n2);

        // PAE over header, nonce, ciphertext, footer, implicit assertion.
        var pae_parts: [5][]const u8 = .{
            pae_header,
            nonce,
            ciphertext,
            footer,
            implicit_assertion,
        };
        const pae = try util.preAuthEncodeAlloc(allocator, &pae_parts);
        defer util.secureFree(allocator, pae);

        var tag: [mac_bytes]u8 = undefined;
        var tag_hasher = Blake2b(mac_bytes * 8).init(.{});
        defer util.secureZero(std.mem.asBytes(&tag_hasher));
        setBlake2bKey(&tag_hasher, &keys.ak);
        tag_hasher.update(pae);
        tag_hasher.final(&tag);

        // Payload = nonce || ciphertext || tag
        const raw_payload = try allocator.alloc(u8, nonce_bytes + ciphertext.len + mac_bytes);
        defer util.secureFree(allocator, raw_payload);
        @memcpy(raw_payload[0..nonce_bytes], nonce);
        @memcpy(raw_payload[nonce_bytes .. nonce_bytes + ciphertext.len], ciphertext);
        @memcpy(raw_payload[nonce_bytes + ciphertext.len ..], &tag);

        return try token_mod.serialize(allocator, .v4, .local, raw_payload, footer);
    }

    /// Decrypt a PASETO token string, returning the plaintext message.
    /// Caller owns the returned buffer.
    pub fn decrypt(
        self: Local,
        allocator: std.mem.Allocator,
        token_str: []const u8,
        implicit_assertion: []const u8,
    ) ![]u8 {
        return try self.decryptBorrowed(allocator, token_str, implicit_assertion);
    }

    /// Pointer-receiver variant for freestanding callers that must avoid an
    /// extra key copy in exported linear memory.
    pub fn decryptBorrowed(
        self: *const Local,
        allocator: std.mem.Allocator,
        token_str: []const u8,
        implicit_assertion: []const u8,
    ) ![]u8 {
        var tok = try token_mod.parse(allocator, token_str);
        defer tok.deinit();
        return try self.decryptTokenBorrowed(allocator, &tok, implicit_assertion);
    }

    pub fn decryptWithFooter(
        self: Local,
        allocator: std.mem.Allocator,
        token_str: []const u8,
        implicit_assertion: []const u8,
    ) !claims_mod.Result {
        return try self.decryptWithFooterBorrowed(allocator, token_str, implicit_assertion);
    }

    /// Footer-preserving pointer-receiver variant for freestanding callers.
    pub fn decryptWithFooterBorrowed(
        self: *const Local,
        allocator: std.mem.Allocator,
        token_str: []const u8,
        implicit_assertion: []const u8,
    ) !claims_mod.Result {
        var tok = try token_mod.parse(allocator, token_str);
        defer tok.deinit();
        const plaintext = try self.decryptTokenBorrowed(allocator, &tok, implicit_assertion);
        errdefer util.secureFree(allocator, plaintext);
        const footer = try allocator.dupe(u8, tok.footer);
        errdefer util.secureFree(allocator, footer);
        return .{ .claims_bytes = plaintext, .footer = footer, .allocator = allocator };
    }

    /// Decrypt using an already-parsed Token. The token is borrowed for the
    /// duration of the call and is not modified.
    pub fn decryptToken(
        self: Local,
        allocator: std.mem.Allocator,
        tok: *const token_mod.Token,
        implicit_assertion: []const u8,
    ) ![]u8 {
        return try self.decryptTokenBorrowed(allocator, tok, implicit_assertion);
    }

    /// Parsed-token pointer-receiver variant used by the freestanding ABI.
    pub fn decryptTokenBorrowed(
        self: *const Local,
        allocator: std.mem.Allocator,
        tok: *const token_mod.Token,
        implicit_assertion: []const u8,
    ) ![]u8 {
        if (tok.version != .v4 or tok.purpose != .local) return Error.WrongPurpose;
        const payload = tok.payload;
        if (payload.len < nonce_bytes + mac_bytes) return Error.MessageTooShort;

        const nonce = payload[0..nonce_bytes];
        const ciphertext = payload[nonce_bytes .. payload.len - mac_bytes];
        const tag = payload[payload.len - mac_bytes ..];

        var keys = deriveKeys(&self.key, nonce);
        defer util.secureZero(std.mem.asBytes(&keys));

        var pae_parts: [5][]const u8 = .{
            pae_header,
            nonce,
            ciphertext,
            tok.footer,
            implicit_assertion,
        };
        const pae = try util.preAuthEncodeAlloc(allocator, &pae_parts);
        defer util.secureFree(allocator, pae);

        var expected_tag: [mac_bytes]u8 = undefined;
        var tag_hasher = Blake2b(mac_bytes * 8).init(.{});
        defer util.secureZero(std.mem.asBytes(&tag_hasher));
        setBlake2bKey(&tag_hasher, &keys.ak);
        tag_hasher.update(pae);
        tag_hasher.final(&expected_tag);

        if (!util.constantTimeEqual(tag, &expected_tag)) return Error.InvalidAuthenticator;

        const plaintext = try allocator.alloc(u8, ciphertext.len);
        errdefer util.secureFree(allocator, plaintext);
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

fn deriveKeys(key: *const [key_bytes]u8, nonce: *const [nonce_bytes]u8) DerivedKeys {
    var tmp: [56]u8 = undefined;
    defer util.secureZero(&tmp);
    var out: DerivedKeys = undefined;

    // tmp = BLAKE2b-56(key=key, data="paseto-encryption-key"||nonce)
    var h = Blake2b(56 * 8).init(.{});
    defer util.secureZero(std.mem.asBytes(&h));
    setBlake2bKey(&h, key);
    h.update("paseto-encryption-key");
    h.update(nonce);
    h.final(&tmp);

    @memcpy(&out.ek, tmp[0..32]);
    @memcpy(&out.n2, tmp[32..56]);

    // ak = BLAKE2b-32(key=key, data="paseto-auth-key-for-aead"||nonce)
    var h2 = Blake2b(32 * 8).init(.{});
    defer util.secureZero(std.mem.asBytes(&h2));
    setBlake2bKey(&h2, key);
    h2.update("paseto-auth-key-for-aead");
    h2.update(nonce);
    h2.final(&out.ak);

    return out;
}

/// Install a BLAKE2b key directly into a caller-owned state. Zig 0.16's keyed
/// `init` returns a state containing the padded key block by value, which can
/// leave the temporary return frame in exported WASM stack memory. Building
/// the same parameter block in place gives the caller one state to wipe.
inline fn setBlake2bKey(hasher: anytype, key: []const u8) void {
    std.debug.assert(key.len > 0 and key.len <= 64);
    hasher.h[0] ^= @as(u64, key.len << 8);
    @memset(&hasher.buf, 0);
    @memcpy(hasher.buf[0..key.len], key);
    hasher.buf_len = Blake2b(8).block_length;
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
