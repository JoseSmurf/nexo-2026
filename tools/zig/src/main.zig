const std = @import("std");
const verify_mod = @import("verify.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const argv = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, argv);

    if (argv.len < 2) {
        usage();
        std.process.exit(2);
    }

    if (std.mem.eql(u8, argv[1], "verify")) {
        if (argv.len != 3) {
            usage();
            std.process.exit(2);
        }
        const code = verifyFile(alloc, argv[2]) catch {
            std.debug.print("io_error: failed to verify file: {s}\n", .{argv[2]});
            std.process.exit(4);
        };
        std.process.exit(code);
    }

    usage();
    std.process.exit(2);
}

fn usage() void {
    std.debug.print(
        \\nexo-audit (Zig) — forensic verifier for audit.jsonl
        \\
        \\USAGE:
        \\  nexo-audit verify <path/to/audit.jsonl>
        \\
        \\EXIT CODES:
        \\  0 ok
        \\  2 schema invalid
        \\  3 tampering detected (audit_hash mismatch)
        \\  4 io error
        \\  5 mixed failures (schema + tampering in same file)
        \\
        \\
    , .{});
}

fn verifyFile(alloc: std.mem.Allocator, path: []const u8) !u8 {
    const options = verifyOptionsFromEnv(alloc);

    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var br = std.io.bufferedReader(file.reader());
    const reader = br.reader();

    var any_schema = false;
    var any_tamper = false;
    var total: usize = 0;
    var ok: usize = 0;
    var line_no: usize = 0;

    while (true) {
        const maybe_line = try reader.readUntilDelimiterOrEofAlloc(alloc, '\n', 1024 * 1024);
        if (maybe_line == null) break;
        defer alloc.free(maybe_line.?);

        line_no += 1;
        const raw = std.mem.trim(u8, maybe_line.?, " \t\r\n");
        if (raw.len == 0) continue;

        total += 1;
        const res = verify_mod.verifyLineWithOptions(alloc, raw, options);
        switch (res) {
            .Ok => ok += 1,
            .SchemaInvalid => {
                any_schema = true;
                std.debug.print("line {d}: schema_invalid\n", .{line_no});
            },
            .Tampering => {
                any_tamper = true;
                std.debug.print("line {d}: tampering\n", .{line_no});
            },
        }
    }

    std.debug.print("verify: total={d} ok={d} schema_invalid={any} tampering={any}\n", .{
        total, ok, any_schema, any_tamper,
    });

    if (any_schema and any_tamper) return 5;
    if (any_tamper) return 3;
    if (any_schema) return 2;
    return 0;
}

fn verifyOptionsFromEnv(alloc: std.mem.Allocator) verify_mod.VerifyOptions {
    var options = verify_mod.VerifyOptions{};
    const raw = std.process.getEnvVarOwned(alloc, "NEXO_ZIG_LEGACY_SHA3_256") catch return options;
    defer alloc.free(raw);

    if (std.ascii.eqlIgnoreCase(raw, "1") or
        std.ascii.eqlIgnoreCase(raw, "true") or
        std.ascii.eqlIgnoreCase(raw, "yes"))
    {
        options.allow_legacy_sha3_256 = true;
    }
    return options;
}
