const std = @import("std");
const util = @import("util.zig");
const errors = @import("errors.zig");

pub const Error = errors.Error;

pub const Version = enum {
    v3,
    v4,

    pub fn string(self: Version) []const u8 {
        return switch (self) {
            .v3 => "v3",
            .v4 => "v4",
        };
    }

    pub fn paserkPrefix(self: Version) []const u8 {
        return switch (self) {
            .v3 => "k3",
            .v4 => "k4",
        };
    }

    pub fn fromString(s: []const u8) ?Version {
        if (std.mem.eql(u8, s, "v3")) return .v3;
        if (std.mem.eql(u8, s, "v4")) return .v4;
        return null;
    }

    pub fn fromPaserkPrefix(s: []const u8) ?Version {
        if (std.mem.eql(u8, s, "k3")) return .v3;
        if (std.mem.eql(u8, s, "k4")) return .v4;
        return null;
    }
};

pub const Purpose = enum {
    local,
    public,

    pub fn string(self: Purpose) []const u8 {
        return switch (self) {
            .local => "local",
            .public => "public",
        };
    }

    pub fn fromString(s: []const u8) ?Purpose {
        if (std.mem.eql(u8, s, "local")) return .local;
        if (std.mem.eql(u8, s, "public")) return .public;
        return null;
    }
};

/// A parsed PASETO in raw form. `payload` and `footer` are freshly-allocated
/// buffers owned by this `Token` and must be freed with `deinit`.
pub const Token = struct {
    version: Version,
    purpose: Purpose,
    payload: []u8,
    footer: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Token) void {
        self.allocator.free(self.payload);
        self.allocator.free(self.footer);
        self.* = undefined;
    }

    pub fn header(self: Token) []const u8 {
        return switch (self.version) {
            .v3 => switch (self.purpose) {
                .local => "v3.local",
                .public => "v3.public",
            },
            .v4 => switch (self.purpose) {
                .local => "v4.local",
                .public => "v4.public",
            },
        };
    }

    pub fn paeHeader(self: Token) []const u8 {
        return switch (self.version) {
            .v3 => switch (self.purpose) {
                .local => "v3.local.",
                .public => "v3.public.",
            },
            .v4 => switch (self.purpose) {
                .local => "v4.local.",
                .public => "v4.public.",
            },
        };
    }
};

/// Parse a PASETO string into its parts and base64url-decoded payload/footer.
pub fn parse(allocator: std.mem.Allocator, input: []const u8) !Token {
    var it = std.mem.splitScalar(u8, input, '.');
    const version_s = it.next() orelse return Error.InvalidToken;
    const purpose_s = it.next() orelse return Error.InvalidToken;
    const payload_s = it.next() orelse return Error.InvalidToken;
    const footer_s = it.next() orelse "";
    if (it.next() != null) return Error.InvalidToken;

    const version = Version.fromString(version_s) orelse return Error.UnsupportedVersion;
    const purpose = Purpose.fromString(purpose_s) orelse return Error.UnsupportedPurpose;

    const payload = try util.decodeBase64Alloc(allocator, payload_s);
    errdefer allocator.free(payload);

    const footer = try util.decodeBase64Alloc(allocator, footer_s);
    errdefer allocator.free(footer);

    return .{
        .version = version,
        .purpose = purpose,
        .payload = payload,
        .footer = footer,
        .allocator = allocator,
    };
}

/// Build a PASETO string from its parts. Caller owns the returned buffer.
pub fn serialize(
    allocator: std.mem.Allocator,
    version: Version,
    purpose: Purpose,
    raw_payload: []const u8,
    raw_footer: []const u8,
) ![]u8 {
    const payload_encoded_len = util.encodedBase64Len(raw_payload.len);
    const footer_encoded_len = util.encodedBase64Len(raw_footer.len);

    const prefix = paeHeaderOf(version, purpose);
    // prefix already ends with '.' so we subtract 1 when computing total size.
    var total: usize = prefix.len + payload_encoded_len;
    const have_footer = raw_footer.len != 0;
    if (have_footer) total += 1 + footer_encoded_len;

    const out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);

    @memcpy(out[0..prefix.len], prefix);
    var idx: usize = prefix.len;
    _ = util.encodeBase64(out[idx..][0..payload_encoded_len], raw_payload);
    idx += payload_encoded_len;

    if (have_footer) {
        out[idx] = '.';
        idx += 1;
        _ = util.encodeBase64(out[idx..][0..footer_encoded_len], raw_footer);
        idx += footer_encoded_len;
    }

    std.debug.assert(idx == out.len);
    return out;
}

pub fn paeHeaderOf(version: Version, purpose: Purpose) []const u8 {
    return switch (version) {
        .v3 => switch (purpose) {
            .local => "v3.local.",
            .public => "v3.public.",
        },
        .v4 => switch (purpose) {
            .local => "v4.local.",
            .public => "v4.public.",
        },
    };
}

test "round-trip token without footer" {
    const allocator = std.testing.allocator;
    const token_str = try serialize(allocator, .v4, .local, "payload-bytes", "");
    defer allocator.free(token_str);
    try std.testing.expect(std.mem.startsWith(u8, token_str, "v4.local."));
    try std.testing.expect(std.mem.indexOfScalar(u8, token_str[9..], '.') == null);

    var token = try parse(allocator, token_str);
    defer token.deinit();
    try std.testing.expectEqualSlices(u8, "payload-bytes", token.payload);
    try std.testing.expectEqualSlices(u8, "", token.footer);
}

test "round-trip token with footer" {
    const allocator = std.testing.allocator;
    const token_str = try serialize(allocator, .v3, .public, "payload", "fffoooter");
    defer allocator.free(token_str);
    try std.testing.expect(std.mem.startsWith(u8, token_str, "v3.public."));

    var token = try parse(allocator, token_str);
    defer token.deinit();
    try std.testing.expectEqualSlices(u8, "payload", token.payload);
    try std.testing.expectEqualSlices(u8, "fffoooter", token.footer);
}

test "parse rejects unknown header" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.UnsupportedVersion, parse(allocator, "v2.local.aGVsbG8"));
    try std.testing.expectError(Error.UnsupportedPurpose, parse(allocator, "v4.nope.aGVsbG8"));
    try std.testing.expectError(Error.InvalidToken, parse(allocator, "v4.local"));
}
