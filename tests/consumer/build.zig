const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const paseto = b.dependency("paseto", .{
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("paseto", paseto.module("paseto"));

    const exe = b.addExecutable(.{
        .name = "paseto-consumer-smoke",
        .root_module = exe_mod,
    });

    const run = b.addRunArtifact(exe);
    const smoke_step = b.step("smoke", "Run downstream dependency smoke test");
    smoke_step.dependOn(&run.step);
    b.default_step.dependOn(&run.step);
}
