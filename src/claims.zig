const std = @import("std");
const errors = @import("errors.zig");

pub const Error = errors.Error;

pub const Claims = struct {
    json: []const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, json_bytes: []const u8) !Claims {
        const owned = try allocator.dupe(u8, json_bytes);
        return .{ .json = owned, .allocator = allocator };
    }

    pub fn deinit(self: *Claims) void {
        self.allocator.free(self.json);
        self.* = undefined;
    }

    pub fn raw(self: Claims) []const u8 {
        return self.json;
    }

    pub fn parsed(self: Claims) !std.json.Parsed(std.json.Value) {
        return try std.json.parseFromSlice(std.json.Value, self.allocator, self.json, .{});
    }
};

pub const Result = struct {
    claims_bytes: []u8,
    footer: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Result) void {
        self.allocator.free(self.claims_bytes);
        self.allocator.free(self.footer);
        self.* = undefined;
    }
};

pub const Validator = struct {
    verify_exp: bool = true,
    verify_nbf: bool = true,
    verify_iat: bool = true,
    expected_issuer: ?[]const u8 = null,
    expected_audience: ?[]const []const u8 = null,
    expected_subject: ?[]const u8 = null,
    expected_token_identifier: ?[]const u8 = null,
    require_issuer: bool = false,
    require_audience: bool = false,
    require_subject: bool = false,
    require_token_identifier: bool = false,
    /// Optional override (seconds since Unix epoch). Uses wall clock when null.
    now_override: ?i64 = null,

    pub fn validate(self: Validator, claims_bytes: []const u8, allocator: std.mem.Allocator) !void {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, claims_bytes, .{}) catch {
            return Error.InvalidJson;
        };
        defer parsed.deinit();
        if (parsed.value != .object) return Error.InvalidClaim;
        const obj = parsed.value.object;

        const now_s = self.now_override orelse blk: {
            const io = std.Io.Threaded.global_single_threaded.io();
            const ts = std.Io.Clock.real.now(io);
            break :blk ts.toSeconds();
        };

        if (obj.get("exp")) |v| {
            if (self.verify_exp) {
                const t = try parseIsoTimestamp(v);
                if (now_s >= t) return Error.ExpiredToken;
            }
        }
        if (obj.get("nbf")) |v| {
            if (self.verify_nbf) {
                const t = try parseIsoTimestamp(v);
                if (now_s < t) return Error.InactiveToken;
            }
        }
        if (obj.get("iat")) |v| {
            if (self.verify_iat) {
                const t = try parseIsoTimestamp(v);
                if (now_s < t) return Error.ImmatureToken;
            }
        }

        if (self.expected_issuer) |expected| {
            const v = obj.get("iss") orelse {
                return if (self.require_issuer) Error.InvalidIssuer else {};
            };
            if (v != .string) return Error.InvalidIssuer;
            if (!std.mem.eql(u8, v.string, expected)) return Error.InvalidIssuer;
        } else if (self.require_issuer) {
            if (obj.get("iss") == null) return Error.InvalidIssuer;
        }

        if (self.expected_audience) |list| {
            const v = obj.get("aud") orelse {
                return if (self.require_audience) Error.InvalidAudience else {};
            };
            if (v != .string) return Error.InvalidAudience;
            var matched = false;
            for (list) |candidate| {
                if (std.mem.eql(u8, v.string, candidate)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) return Error.InvalidAudience;
        } else if (self.require_audience) {
            if (obj.get("aud") == null) return Error.InvalidAudience;
        }

        if (self.expected_subject) |expected| {
            const v = obj.get("sub") orelse {
                return if (self.require_subject) Error.InvalidSubject else {};
            };
            if (v != .string) return Error.InvalidSubject;
            if (!std.mem.eql(u8, v.string, expected)) return Error.InvalidSubject;
        } else if (self.require_subject) {
            if (obj.get("sub") == null) return Error.InvalidSubject;
        }

        if (self.expected_token_identifier) |expected| {
            const v = obj.get("jti") orelse {
                return if (self.require_token_identifier) Error.InvalidTokenIdentifier else {};
            };
            if (v != .string) return Error.InvalidTokenIdentifier;
            if (!std.mem.eql(u8, v.string, expected)) return Error.InvalidTokenIdentifier;
        } else if (self.require_token_identifier) {
            if (obj.get("jti") == null) return Error.InvalidTokenIdentifier;
        }
    }
};

/// Parse an ISO-8601 timestamp into a Unix epoch second count. Accepts
/// `YYYY-MM-DDTHH:MM:SS(.fff)?(Z|±HH:MM)` forms — the subset emitted by
/// Ruby's `Time#iso8601` and accepted by the PASETO spec.
pub fn parseIsoTimestamp(v: std.json.Value) !i64 {
    if (v != .string) return Error.InvalidTime;
    const s = v.string;
    if (s.len < 19) return Error.InvalidTime;

    var idx: usize = 0;
    const year = try parseDecimal(i32, s, &idx, 4);
    if (idx >= s.len or s[idx] != '-') return Error.InvalidTime;
    idx += 1;
    const month = try parseDecimal(u8, s, &idx, 2);
    if (idx >= s.len or s[idx] != '-') return Error.InvalidTime;
    idx += 1;
    const day = try parseDecimal(u8, s, &idx, 2);
    if (idx >= s.len or (s[idx] != 'T' and s[idx] != ' ')) return Error.InvalidTime;
    idx += 1;
    const hour = try parseDecimal(u8, s, &idx, 2);
    if (idx >= s.len or s[idx] != ':') return Error.InvalidTime;
    idx += 1;
    const minute = try parseDecimal(u8, s, &idx, 2);
    if (idx >= s.len or s[idx] != ':') return Error.InvalidTime;
    idx += 1;
    const second = try parseDecimal(u8, s, &idx, 2);

    // Skip optional fractional seconds.
    if (idx < s.len and s[idx] == '.') {
        idx += 1;
        while (idx < s.len and s[idx] >= '0' and s[idx] <= '9') : (idx += 1) {}
    }

    var offset_seconds: i32 = 0;
    if (idx >= s.len) return Error.InvalidTime;
    if (s[idx] == 'Z' or s[idx] == 'z') {
        idx += 1;
    } else if (s[idx] == '+' or s[idx] == '-') {
        const sign: i32 = if (s[idx] == '+') 1 else -1;
        idx += 1;
        const oh = try parseDecimal(u8, s, &idx, 2);
        if (idx < s.len and s[idx] == ':') idx += 1;
        const om = try parseDecimal(u8, s, &idx, 2);
        offset_seconds = sign * (@as(i32, oh) * 3600 + @as(i32, om) * 60);
    } else {
        return Error.InvalidTime;
    }
    if (idx != s.len) return Error.InvalidTime;

    const days = try daysFromCivil(year, month, day);
    const naive_seconds = @as(i64, days) * 86400 +
        @as(i64, hour) * 3600 +
        @as(i64, minute) * 60 +
        @as(i64, second);
    return naive_seconds - @as(i64, offset_seconds);
}

fn parseDecimal(comptime T: type, s: []const u8, idx: *usize, width: usize) !T {
    if (idx.* + width > s.len) return Error.InvalidTime;
    const chunk = s[idx.* .. idx.* + width];
    var acc: T = 0;
    for (chunk) |c| {
        if (c < '0' or c > '9') return Error.InvalidTime;
        acc = acc * 10 + (c - '0');
    }
    idx.* += width;
    return acc;
}

/// Civil to days conversion from Howard Hinnant's low-level date
/// algorithms (public domain). Returns days since 1970-01-01.
fn daysFromCivil(y: i32, m: u8, d: u8) !i32 {
    if (m < 1 or m > 12) return Error.InvalidTime;
    if (d < 1 or d > 31) return Error.InvalidTime;
    const year = if (m <= 2) y - 1 else y;
    const era = @divFloor(year, 400);
    const yoe = @as(u32, @intCast(year - era * 400));
    const mp: u32 = @as(u32, if (m > 2) m - 3 else m + 9);
    const doy: u32 = (153 * mp + 2) / 5 + @as(u32, d) - 1;
    const doe: u32 = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const days = era * 146097 + @as(i32, @intCast(doe)) - 719468;
    return days;
}

test "ISO8601 parsing" {
    const v = std.json.Value{ .string = "2022-01-01T00:00:00+00:00" };
    try std.testing.expectEqual(@as(i64, 1640995200), try parseIsoTimestamp(v));
    const v2 = std.json.Value{ .string = "2022-01-01T00:00:00.123Z" };
    try std.testing.expectEqual(@as(i64, 1640995200), try parseIsoTimestamp(v2));
    const v3 = std.json.Value{ .string = "2022-01-01T05:30:00+05:30" };
    try std.testing.expectEqual(@as(i64, 1640995200), try parseIsoTimestamp(v3));
}

test "validator checks exp" {
    const allocator = std.testing.allocator;
    const claims = "{\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    var val: Validator = .{ .now_override = 1_700_000_000 };
    try std.testing.expectError(Error.ExpiredToken, val.validate(claims, allocator));

    val.now_override = 1_600_000_000;
    try val.validate(claims, allocator);
}
