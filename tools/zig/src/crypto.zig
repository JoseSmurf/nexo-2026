const std = @import("std");

pub const HashAlgorithm = enum {
    blake3,
    blake3_256,
    sha3_256_legacy,
    shake256_256,
    shake256_384,
    shake256_512,
    hybrid_shake512_blake3_256,

    pub fn parse(s: []const u8) ?HashAlgorithm {
        if (std.mem.eql(u8, s, "blake3")) return .blake3;
        if (std.mem.eql(u8, s, "blake3-256")) return .blake3_256;
        if (std.mem.eql(u8, s, "shake256-256")) return .shake256_256;
        if (std.mem.eql(u8, s, "shake256-384")) return .shake256_384;
        if (std.mem.eql(u8, s, "shake256-512")) return .shake256_512;
        if (std.mem.eql(u8, s, "shake256-512+blake3-256")) return .hybrid_shake512_blake3_256;
        return null;
    }

    pub fn outputLenHex(self: HashAlgorithm) usize {
        return switch (self) {
            .blake3, .blake3_256, .sha3_256_legacy => 64,
            .shake256_256 => 64,
            .shake256_384 => 96,
            .shake256_512 => 128,
            .hybrid_shake512_blake3_256 => 192,
        };
    }

    pub fn isHybrid(self: HashAlgorithm) bool {
        return self == .hybrid_shake512_blake3_256;
    }
};

pub const Hasher = union(HashAlgorithm) {
    blake3: std.crypto.hash.Blake3,
    blake3_256: std.crypto.hash.Blake3,
    sha3_256_legacy: std.crypto.hash.sha3.Sha3_256,
    shake256_256: std.crypto.hash.sha3.Shake256,
    shake256_384: std.crypto.hash.sha3.Shake256,
    shake256_512: std.crypto.hash.sha3.Shake256,
    hybrid_shake512_blake3_256: void,

    pub fn init(algo: HashAlgorithm) Hasher {
        return switch (algo) {
            .blake3 => .{ .blake3 = std.crypto.hash.Blake3.init(.{}) },
            .blake3_256 => .{ .blake3_256 = std.crypto.hash.Blake3.init(.{}) },
            .sha3_256_legacy => .{ .sha3_256_legacy = std.crypto.hash.sha3.Sha3_256.init(.{}) },
            .shake256_256 => .{ .shake256_256 = std.crypto.hash.sha3.Shake256.init(.{}) },
            .shake256_384 => .{ .shake256_384 = std.crypto.hash.sha3.Shake256.init(.{}) },
            .shake256_512 => .{ .shake256_512 = std.crypto.hash.sha3.Shake256.init(.{}) },
            .hybrid_shake512_blake3_256 => .{ .hybrid_shake512_blake3_256 = {} },
        };
    }

    pub fn update(self: *Hasher, data: []const u8) void {
        switch (self.*) {
            .blake3 => |*h| h.update(data),
            .blake3_256 => |*h| h.update(data),
            .sha3_256_legacy => |*h| h.update(data),
            .shake256_256 => |*h| h.update(data),
            .shake256_384 => |*h| h.update(data),
            .shake256_512 => |*h| h.update(data),
            .hybrid_shake512_blake3_256 => unreachable,
        }
    }

    pub fn finalAlloc(self: *Hasher, alloc: std.mem.Allocator) ![]u8 {
        switch (self.*) {
            .blake3 => |*h| {
                var tmp: [32]u8 = undefined;
                h.final(&tmp);
                const out = try alloc.alloc(u8, 32);
                @memcpy(out, &tmp);
                return out;
            },
            .blake3_256 => |*h| {
                var tmp: [32]u8 = undefined;
                h.final(&tmp);
                const out = try alloc.alloc(u8, 32);
                @memcpy(out, &tmp);
                return out;
            },
            .sha3_256_legacy => |*h| {
                var tmp: [32]u8 = undefined;
                h.final(&tmp);
                const out = try alloc.alloc(u8, 32);
                @memcpy(out, &tmp);
                return out;
            },
            .shake256_256 => |*h| {
                const out = try alloc.alloc(u8, 32);
                h.final(out);
                return out;
            },
            .shake256_384 => |*h| {
                const out = try alloc.alloc(u8, 48);
                h.final(out);
                return out;
            },
            .shake256_512 => |*h| {
                const out = try alloc.alloc(u8, 64);
                h.final(out);
                return out;
            },
            .hybrid_shake512_blake3_256 => unreachable,
        }
    }
};

fn littleEndian() std.builtin.Endian {
    const Endian = std.builtin.Endian;
    return @field(Endian, if (@hasField(Endian, "little")) "little" else "Little");
}

pub fn hashField(h: *Hasher, tag: []const u8, data: []const u8) void {
    var tlen: [4]u8 = undefined;
    const tlen_u32 = std.math.cast(u32, tag.len) orelse unreachable;
    std.mem.writeInt(u32, &tlen, tlen_u32, littleEndian());
    h.update(&tlen);
    h.update(tag);

    var dlen: [4]u8 = undefined;
    const dlen_u32 = std.math.cast(u32, data.len) orelse unreachable;
    std.mem.writeInt(u32, &dlen, dlen_u32, littleEndian());
    h.update(&dlen);
    h.update(data);
}

pub fn pushU64Le(h: *Hasher, v: u64) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, v, littleEndian());
    h.update(&buf);
}
