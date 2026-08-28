//! Freestanding WASM ABI for the PASETO v4.local operations used by Deno.
//!
//! The host owns randomness and supplies the 32-byte v4.local nonce to `seal`.
//! Successful calls publish dynamically-sized results through an eight-byte
//! little-endian `{ pointer, length }` descriptor.

const std = @import("std");
const builtin = @import("builtin");
const util = @import("util.zig");
const local_mod = @import("v4/local.zig");
const id_mod = @import("paserk/id.zig");

pub const abi_version: u32 = 1;
pub const key_bytes: usize = local_mod.key_bytes;
pub const nonce_bytes: usize = local_mod.nonce_bytes;
pub const result_descriptor_bytes: usize = 8;
pub const open_result_header_bytes: usize = 8;
pub const local_key_id_bytes: usize = id_mod.string_bytes;

const seal_frame_header_bytes = key_bytes + nonce_bytes + 12;
const open_frame_header_bytes = key_bytes + 8;
const max_abi_input_bytes = util.max_token_string_bytes + seal_frame_header_bytes;

// v4.local session payloads are small in normal use, but the arena is large
// enough to process the library's one MiB token limit without growing memory.
// Keeping a fixed arena also lets resetAllocator wipe every host and crypto
// allocation deterministically.
var heap_buffer: [8 * 1024 * 1024]u8 = @splat(0);
var fba = std.heap.FixedBufferAllocator.init(&heap_buffer);
var arena_peak: usize = 0;

fn recordArenaPeak() void {
    if (fba.end_index > arena_peak) arena_peak = fba.end_index;
}

fn arenaAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
    _ = ctx;
    const result = fba.allocator().rawAlloc(len, alignment, ret_addr);
    recordArenaPeak();
    return result;
}

fn arenaResize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
    _ = ctx;
    const result = fba.allocator().rawResize(memory, alignment, new_len, ret_addr);
    recordArenaPeak();
    return result;
}

fn arenaRemap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
    _ = ctx;
    const result = fba.allocator().rawRemap(memory, alignment, new_len, ret_addr);
    recordArenaPeak();
    return result;
}

fn arenaFree(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
    _ = ctx;
    fba.allocator().rawFree(memory, alignment, ret_addr);
}

const arena_vtable = std.mem.Allocator.VTable{
    .alloc = arenaAlloc,
    .resize = arenaResize,
    .remap = arenaRemap,
    .free = arenaFree,
};

fn arenaAllocator() std.mem.Allocator {
    return .{ .ptr = &fba, .vtable = &arena_vtable };
}

pub const Status = enum(i32) {
    ok = 0,
    crypto_error = 1,
    invalid_input = 2,
    out_of_memory = 3,
};

/// Native-test view of one ABI invocation. Production callers receive the same
/// status and bytes through the exported result descriptor.
pub const Invocation = struct {
    status: Status,
    output: ?[]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Invocation) void {
        if (self.output) |output| util.secureFree(self.allocator, output);
        self.* = undefined;
    }
};

const SealFrame = struct {
    key: []const u8,
    nonce: []const u8,
    message: []const u8,
    footer: []const u8,
    implicit_assertion: []const u8,
};

const OpenFrame = struct {
    key: []const u8,
    token: []const u8,
    implicit_assertion: []const u8,
};

pub export fn version() u32 {
    return abi_version;
}

pub export fn localKeyIdLen() u32 {
    return @intCast(local_key_id_bytes);
}

pub export fn openResultHeaderLen() u32 {
    return @intCast(open_result_header_bytes);
}

pub export fn allocate(len: u32) u32 {
    if (len == 0 or !heapFitsU32Pointers()) return 0;
    const bytes = arenaAllocator().alloc(u8, len) catch return 0;
    @memset(bytes, 0);
    return @intCast(@intFromPtr(bytes.ptr));
}

pub export fn free(ptr: u32, len: u32) void {
    const bytes = heapSlice(ptr, len) catch return;
    @memset(bytes, 0);
    // FixedBufferAllocator only reclaims in stack order. resetAllocator is the
    // operation boundary that reclaims the whole arena.
}

pub export fn resetAllocator() void {
    resetArenaAllocator();
}

fn resetArenaAllocator() void {
    const wipe_len = @max(arena_peak, fba.end_index);
    @memset(heap_buffer[0..wipe_len], 0);
    arena_peak = 0;
    fba.reset();
}

pub export fn seal(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    return runExport(input_ptr, input_len, out_ptr, invokeSeal);
}

pub export fn open(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    return runExport(input_ptr, input_len, out_ptr, invokeOpen);
}

pub export fn localKeyId(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    return runExport(input_ptr, input_len, out_ptr, invokeLocalKeyId);
}

fn runExport(
    input_ptr: u32,
    input_len: u32,
    out_ptr: u32,
    comptime invoke: fn (std.mem.Allocator, []const u8) Invocation,
) i32 {
    validateOutputDescriptor(out_ptr) catch return @intFromEnum(Status.invalid_input);
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    var invocation = invoke(arenaAllocator(), input);
    if (invocation.status != .ok) {
        const status = invocation.status;
        invocation.deinit();
        return @intFromEnum(status);
    }

    const output = invocation.output orelse {
        invocation.deinit();
        return @intFromEnum(Status.crypto_error);
    };
    writeResultDescriptor(out_ptr, @intCast(@intFromPtr(output.ptr)), @intCast(output.len)) catch {
        invocation.deinit();
        return @intFromEnum(Status.invalid_input);
    };

    // Ownership passes to the host. `free` wipes the range promptly and
    // `resetAllocator` wipes and reclaims the complete arena.
    invocation.output = null;
    return @intFromEnum(Status.ok);
}

fn invokeSeal(allocator: std.mem.Allocator, input: []const u8) Invocation {
    const frame = parseSealFrame(input) catch return failure(allocator, .invalid_input);
    const output = sealFrame(allocator, frame) catch |err| return failure(allocator, mapSealError(err));
    return success(allocator, output);
}

fn invokeOpen(allocator: std.mem.Allocator, input: []const u8) Invocation {
    const frame = parseOpenFrame(input) catch return failure(allocator, .invalid_input);
    const output = openFrame(allocator, frame) catch |err| return failure(allocator, mapOpenError(err));
    return success(allocator, output);
}

fn invokeLocalKeyId(allocator: std.mem.Allocator, input: []const u8) Invocation {
    if (input.len != key_bytes) return failure(allocator, .invalid_input);

    var key = local_mod.Local.fromBytes(input) catch return failure(allocator, .invalid_input);
    defer util.secureZero(&key.key);
    const id = id_mod.lid(.v4, &key.key) catch return failure(allocator, .crypto_error);
    var encoded = id.toArray();
    defer util.secureZero(&encoded);
    const output = allocator.dupe(u8, &encoded) catch return failure(allocator, .out_of_memory);
    return success(allocator, output);
}

fn sealFrame(allocator: std.mem.Allocator, frame: SealFrame) ![]u8 {
    var key = try local_mod.Local.fromBytes(frame.key);
    defer util.secureZero(&key.key);
    var nonce = frame.nonce[0..nonce_bytes].*;
    defer util.secureZero(&nonce);

    return try key.encryptWithNonce(
        allocator,
        frame.message,
        &nonce,
        frame.footer,
        frame.implicit_assertion,
    );
}

fn openFrame(allocator: std.mem.Allocator, frame: OpenFrame) ![]u8 {
    var key = try local_mod.Local.fromBytes(frame.key);
    defer util.secureZero(&key.key);
    var result = key.decryptWithFooterBorrowed(allocator, frame.token, frame.implicit_assertion) catch |err| {
        // Keep the error path explicit at the WASM boundary. In optimized
        // freestanding builds this prevents a spilled key copy from surviving
        // until the next call when authentication fails before decryption.
        util.secureZero(&key.key);
        return err;
    };
    defer result.deinit();

    var output_len = std.math.add(usize, open_result_header_bytes, result.claims_bytes.len) catch return error.Overflow;
    output_len = std.math.add(usize, output_len, result.footer.len) catch return error.Overflow;
    if (result.claims_bytes.len > std.math.maxInt(u32) or result.footer.len > std.math.maxInt(u32)) {
        return error.Overflow;
    }

    const output = try allocator.alloc(u8, output_len);
    errdefer util.secureFree(allocator, output);
    std.mem.writeInt(u32, output[0..4], @intCast(result.claims_bytes.len), .little);
    std.mem.writeInt(u32, output[4..8], @intCast(result.footer.len), .little);
    @memcpy(output[8..][0..result.claims_bytes.len], result.claims_bytes);
    @memcpy(output[8 + result.claims_bytes.len ..], result.footer);
    return output;
}

fn parseSealFrame(input: []const u8) !SealFrame {
    if (input.len < seal_frame_header_bytes or input.len > max_abi_input_bytes) return error.InvalidInput;

    var offset: usize = 0;
    const key = try readSlice(input, &offset, key_bytes);
    const nonce = try readSlice(input, &offset, nonce_bytes);
    const message_len = try readU32(input, &offset);
    const footer_len = try readU32(input, &offset);
    const implicit_assertion_len = try readU32(input, &offset);
    const message = try readSlice(input, &offset, message_len);
    const footer = try readSlice(input, &offset, footer_len);
    const implicit_assertion = try readSlice(input, &offset, implicit_assertion_len);
    if (offset != input.len) return error.InvalidInput;

    return .{
        .key = key,
        .nonce = nonce,
        .message = message,
        .footer = footer,
        .implicit_assertion = implicit_assertion,
    };
}

fn parseOpenFrame(input: []const u8) !OpenFrame {
    if (input.len < open_frame_header_bytes or input.len > max_abi_input_bytes) return error.InvalidInput;

    var offset: usize = 0;
    const key = try readSlice(input, &offset, key_bytes);
    const token_len = try readU32(input, &offset);
    const implicit_assertion_len = try readU32(input, &offset);
    const token = try readSlice(input, &offset, token_len);
    const implicit_assertion = try readSlice(input, &offset, implicit_assertion_len);
    if (offset != input.len or token.len == 0) return error.InvalidInput;

    return .{
        .key = key,
        .token = token,
        .implicit_assertion = implicit_assertion,
    };
}

fn success(allocator: std.mem.Allocator, output: []u8) Invocation {
    return .{ .status = .ok, .output = output, .allocator = allocator };
}

fn failure(allocator: std.mem.Allocator, status: Status) Invocation {
    return .{ .status = status, .output = null, .allocator = allocator };
}

fn mapSealError(err: anyerror) Status {
    return switch (err) {
        error.OutOfMemory => .out_of_memory,
        error.InvalidToken, error.Overflow => .invalid_input,
        else => .crypto_error,
    };
}

fn mapOpenError(err: anyerror) Status {
    return switch (err) {
        error.OutOfMemory => .out_of_memory,
        error.Overflow => .invalid_input,
        else => .crypto_error,
    };
}

fn readSlice(input: []const u8, offset: *usize, len: usize) ![]const u8 {
    if (offset.* > input.len or input.len - offset.* < len) return error.InvalidInput;
    const output = input[offset.*..][0..len];
    offset.* += len;
    return output;
}

fn readU32(input: []const u8, offset: *usize) !usize {
    const bytes = try readSlice(input, offset, 4);
    return @intCast(std.mem.readInt(u32, bytes[0..4], .little));
}

fn writeResultDescriptor(out_ptr: u32, result_ptr: u32, result_len: u32) !void {
    const output = try heapSlice(out_ptr, result_descriptor_bytes);
    std.mem.writeInt(u32, output[0..4], result_ptr, .little);
    std.mem.writeInt(u32, output[4..8], result_len, .little);
}

fn validateOutputDescriptor(out_ptr: u32) !void {
    _ = try heapSlice(out_ptr, result_descriptor_bytes);
}

fn inputSlice(ptr: u32, len: u32) ![]const u8 {
    return try heapSlice(ptr, len);
}

fn heapSlice(ptr: u32, len: usize) ![]u8 {
    if (len > std.math.maxInt(u32)) return error.InvalidInput;
    if (len == 0) {
        if (ptr == 0) return heap_buffer[0..0];
        if (!rangeInHeap(ptr, 0)) return error.InvalidInput;
        const start = @as(usize, ptr) - heapStart();
        return heap_buffer[start..start];
    }
    if (!rangeInHeap(ptr, @intCast(len))) return error.InvalidInput;
    const start = @as(usize, ptr) - heapStart();
    return heap_buffer[start..][0..len];
}

fn rangeInHeap(ptr: u32, len: u32) bool {
    const start = @as(usize, ptr);
    const end = std.math.add(usize, start, len) catch return false;
    const heap_start = heapStart();
    const heap_end = heapEnd();
    return start >= heap_start and end <= heap_end and end >= start;
}

fn heapFitsU32Pointers() bool {
    return heapEnd() <= std.math.maxInt(u32);
}

fn heapStart() usize {
    return @intFromPtr(&heap_buffer[0]);
}

fn heapEnd() usize {
    return heapStart() + heap_buffer.len;
}

pub const test_api = if (builtin.is_test) struct {
    pub fn seal(allocator: std.mem.Allocator, input: []const u8) Invocation {
        return invokeSeal(allocator, input);
    }

    pub fn open(allocator: std.mem.Allocator, input: []const u8) Invocation {
        return invokeOpen(allocator, input);
    }

    pub fn localKeyId(allocator: std.mem.Allocator, input: []const u8) Invocation {
        return invokeLocalKeyId(allocator, input);
    }

    pub fn arenaAllocate(len: usize) ![]u8 {
        return try arenaAllocator().alloc(u8, len);
    }

    pub fn resetArena() void {
        resetArenaAllocator();
    }

    pub fn arenaNonZeroBytes() usize {
        var count: usize = 0;
        for (heap_buffer[0..]) |byte| {
            if (byte != 0) count += 1;
        }
        return count;
    }
} else struct {};
