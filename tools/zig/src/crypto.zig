const std = @import("std");

pub const HashAlgorithm = enum {
    blake3,
    sha3_256,

    pub fn parse(s: []const u8) ?HashAlgorithm {
        if (std.mem.eql(u8, s, "blake3")) return .blake3;
        if (std.mem.eql(u8, s, "sha3-256")) return .sha3_256;
        return null;
    }
};

pub const Hasher = union(HashAlgorithm) {
    blake3: std.crypto.hash.Blake3,
    sha3_256: std.crypto.hash.sha3.Sha3_256,

    pub fn init(algo: HashAlgorithm) Hasher {
        return switch (algo) {
            .blake3 => .{ .blake3 = std.crypto.hash.Blake3.init(.{}) },
            .sha3_256 => .{ .sha3_256 = std.crypto.hash.sha3.Sha3_256.init(.{}) },
        };
    }

    pub fn update(self: *Hasher, data: []const u8) void {
        switch (self.*) {
            .blake3 => |*h| h.update(data),
            .sha3_256 => |*h| h.update(data),
        }
    }

    pub fn final(self: *Hasher, out: *[32]u8) void {
        switch (self.*) {
            .blake3 => |*h| h.final(out),
            .sha3_256 => |*h| h.final(out),
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
