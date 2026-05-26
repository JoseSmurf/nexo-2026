const std = @import("std");
const verify_mod = @import("verify.zig");

pub fn main(init: std.process.Init) !void {
    const alloc = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(alloc);

    if (argv.len < 2) {
        usage();
        std.process.exit(2);
    }

    if (std.mem.eql(u8, argv[1], "verify")) {
        var require_chain = false;
        var path_idx: usize = 2;
        if (argv.len == 4 and std.mem.eql(u8, argv[2], "--require-chain")) {
            require_chain = true;
            path_idx = 3;
        } else if (argv.len != 3) {
            usage();
            std.process.exit(2);
        }
        const code = verifyFile(alloc, init.minimal.environ, argv[path_idx], require_chain) catch {
            std.debug.print("io_error: failed to verify file: {s}\n", .{argv[path_idx]});
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
        \\  nexo-audit verify --require-chain <path/to/audit.jsonl>
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

fn verifyFile(
    alloc: std.mem.Allocator,
    environ: std.process.Environ,
    path: []const u8,
    require_chain: bool,
) !u8 {
    const options = verifyOptionsFromEnv(environ, alloc);
    const content = try readFileAllocCompat(alloc, path, 1024 * 1024 * 32);
    defer alloc.free(content);

    var chain_state = verify_mod.RequireChainState{};
    defer chain_state.deinit(alloc);

    var any_schema = false;
    var any_tamper = false;
    var total: usize = 0;
    var ok: usize = 0;
    var line_no: usize = 0;

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        line_no += 1;
        const raw = std.mem.trim(u8, line, " \t\r\n");
        if (raw.len == 0) continue;

        total += 1;
        const res = if (require_chain)
            verify_mod.verifyLineWithOptionsRequireChain(alloc, raw, options, &chain_state)
        else
            verify_mod.verifyLineWithOptions(alloc, raw, options);
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

fn verifyOptionsFromEnv(environ: std.process.Environ, alloc: std.mem.Allocator) verify_mod.VerifyOptions {
    var options = verify_mod.VerifyOptions{};
    const raw = if (@hasDecl(std.process, "getEnvVarOwned"))
        std.process.getEnvVarOwned(alloc, "NEXO_ZIG_LEGACY_SHA3_256") catch return options
    else
        environ.getAlloc(alloc, "NEXO_ZIG_LEGACY_SHA3_256") catch return options;
    defer alloc.free(raw);

    if (std.ascii.eqlIgnoreCase(raw, "1") or
        std.ascii.eqlIgnoreCase(raw, "true") or
        std.ascii.eqlIgnoreCase(raw, "yes"))
    {
        options.allow_legacy_sha3_256 = true;
    }
    return options;
}

fn readFileAllocCompat(alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    if (@hasDecl(std.fs, "cwd")) {
        return std.fs.cwd().readFileAlloc(alloc, path, max_bytes);
    }

    var io_instance: std.Io.Threaded = .init(alloc, .{});
    defer io_instance.deinit();
    const io = io_instance.io();
    return std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(max_bytes));
}
