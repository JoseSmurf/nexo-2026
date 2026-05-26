const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = addExecutableCompat(b, "nexo-audit", "src/main.zig", target, optimize);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run nexo-audit");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = addTestCompat(b, "src/verify.zig", target, optimize);
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run Zig verifier tests");
    test_step.dependOn(&run_unit_tests.step);
}

fn compatPath(b: *std.Build, p: []const u8) std.Build.LazyPath {
    if (@hasDecl(std.Build, "path")) {
        return b.path(p);
    }
    return .{ .path = p };
}

fn createModuleCompat(
    b: *std.Build,
    root: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = compatPath(b, root),
        .target = target,
        .optimize = optimize,
    });
}

fn addExecutableCompat(
    b: *std.Build,
    name: []const u8,
    root: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    if (@hasField(std.Build.ExecutableOptions, "root_source_file")) {
        return b.addExecutable(.{
            .name = name,
            .root_source_file = compatPath(b, root),
            .target = target,
            .optimize = optimize,
        });
    }

    return b.addExecutable(.{
        .name = name,
        .root_module = createModuleCompat(b, root, target, optimize),
    });
}

fn addTestCompat(
    b: *std.Build,
    root: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    if (@hasField(std.Build.TestOptions, "root_source_file")) {
        return b.addTest(.{
            .root_source_file = compatPath(b, root),
            .target = target,
            .optimize = optimize,
        });
    }

    return b.addTest(.{
        .root_module = createModuleCompat(b, root, target, optimize),
    });
}
