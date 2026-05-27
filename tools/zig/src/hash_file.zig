const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const alloc = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(alloc);

    if (argv.len < 2 or argv.len > 3) {
        usage();
        std.process.exit(2);
    }

    const path = argv[1];
    const expected = if (argv.len == 3) argv[2] else null;

    const content = try readFileAllocCompat(alloc, path, 1024 * 1024 * 32);
    defer alloc.free(content);

    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(content);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);

    const hash_hex = try toHexLower(alloc, &hash);

    if (expected) |expected_hex| {
        if (!std.mem.eql(u8, hash_hex, expected_hex)) {
            std.debug.print(
                "hash_mismatch: expected={s} got={s} file={s}\n",
                .{ expected_hex, hash_hex, path },
            );
            std.process.exit(3);
        }
        std.debug.print("hash_ok: {s}\n", .{hash_hex});
        return;
    }

    std.debug.print("{s}\n", .{hash_hex});
}

fn usage() void {
    std.debug.print(
        \\nexo-residual-hash (Zig) - deterministic Blake3 file hash
        \\
        \\USAGE:
        \\  zig run tools/zig/src/hash_file.zig -- <path/to/file>
        \\  zig run tools/zig/src/hash_file.zig -- <path/to/file> <expected_blake3_hex>
        \\
        \\EXIT CODES:
        \\  0 ok
        \\  2 invalid arguments
        \\  3 hash mismatch
        \\  4 io error
        \\
        \\
    , .{});
}

fn toHexLower(alloc: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try alloc.alloc(u8, bytes.len * 2);
    errdefer alloc.free(out);
    const hex = "0123456789abcdef";
    for (bytes, 0..) |byte, idx| {
        out[idx * 2] = hex[byte >> 4];
        out[idx * 2 + 1] = hex[byte & 0x0f];
    }
    return out;
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
