//! Fuzz harness for `src/claims.zig`. Two sub-targets:
//!   - `Validator.validate` on arbitrary JSON-shaped bytes
//!   - `parseIsoTimestamp` on arbitrary strings

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds_validate = [_][]const u8{
    @embedFile("corpus/claims/valid.bin"),
    @embedFile("corpus/claims/not_object.bin"),
    @embedFile("corpus/claims/bad_time.bin"),
    @embedFile("corpus/claims/num_iss.bin"),
    @embedFile("corpus/claims/expired.bin"),
    @embedFile("corpus/claims/garbage.bin"),
};

const seeds_ts = [_][]const u8{
    @embedFile("corpus/claims/ts_zulu.bin"),
    @embedFile("corpus/claims/ts_leap.bin"),
    @embedFile("corpus/claims/ts_impossible.bin"),
};

const validate_default_errors = [_]paseto.Error{
    error.InvalidJson,
    error.InvalidClaim,
    error.InvalidTime,
    error.ExpiredToken,
    error.InactiveToken,
    error.ImmatureToken,
};

const validate_strict_errors = [_]paseto.Error{
    error.InvalidJson,
    error.InvalidClaim,
    error.InvalidTime,
    error.ExpiredToken,
    error.InactiveToken,
    error.ImmatureToken,
    error.InvalidIssuer,
    error.InvalidAudience,
    error.InvalidSubject,
    error.InvalidTokenIdentifier,
};

const ts_errors = [_]paseto.Error{
    error.InvalidTime,
};

test "fuzz: claims.Validator.validate" {
    try std.testing.fuzz({}, validateFuzz, .{ .corpus = &seeds_validate });
}

test "fuzz: claims.parseIsoTimestamp" {
    try std.testing.fuzz({}, timestampFuzz, .{ .corpus = &seeds_ts });
}

fn validateFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var buf: [512]u8 = undefined;
    const n = s.slice(&buf);
    const input = buf[0..n];

    const allocator = std.testing.allocator;

    // Two passes: one default validator, one with required-claim flags on.
    // Same input must always yield the same (success|error) answer between
    // pass A and pass A, and the required-flag pass must not return success
    // when the default pass already found a violation — the checks stack.
    const v_default: paseto.Validator = .{ .now_override = 1_700_000_000 };
    const outcome_a = v_default.validate(input, allocator);
    const outcome_b = v_default.validate(input, allocator);
    try assertSameOutcome(outcome_a, outcome_b);
    if (outcome_a) |_| {} else |err| try support.expectAllowed(err, &validate_default_errors);

    const v_strict: paseto.Validator = .{
        .require_issuer = true,
        .require_audience = true,
        .require_subject = true,
        .require_token_identifier = true,
        .now_override = 1_700_000_000,
    };
    const outcome_strict_a = v_strict.validate(input, allocator);
    const outcome_strict_b = v_strict.validate(input, allocator);
    try assertSameOutcome(outcome_strict_a, outcome_strict_b);
    if (outcome_strict_a) |_| {} else |err| try support.expectAllowed(err, &validate_strict_errors);

    if (outcome_a) |_| {
        if (outcome_strict_a) |_| {} else |_| {}
    } else |_| {
        if (outcome_strict_a) |_| return error.StrictValidatorFixedRejection else |_| {}
    }
}

fn timestampFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var buf: [64]u8 = undefined;
    const n = s.slice(&buf);
    const input = buf[0..n];

    const value = std.json.Value{ .string = input };
    const parsed_a = paseto.claims.parseIsoTimestamp(value) catch |err| {
        return support.expectAllowed(err, &ts_errors);
    };
    const parsed_b = try paseto.claims.parseIsoTimestamp(value);
    try std.testing.expectEqual(parsed_a, parsed_b);
}

fn assertSameOutcome(a: anyerror!void, b: anyerror!void) !void {
    if (a) |_| {
        if (b) |_| return else |_| return error.NonDeterministicValidation;
    } else |ea| {
        if (b) |_| {
            return error.NonDeterministicValidation;
        } else |eb| {
            try std.testing.expectEqual(ea, eb);
        }
    }
}
