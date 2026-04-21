//! Compile-only placeholder so `support.zig` is exercised before real
//! harnesses land. Deleted once Task 2 registers its first harness.

const std = @import("std");
const support = @import("support.zig");

test "fuzz scaffolding placeholder" {
    try std.testing.expectEqual(@as(usize, 4096), support.max_input_bytes);
}
