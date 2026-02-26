const std = @import("std");

pub const VerifyResult = enum {
    Ok,
    SchemaInvalid,
    Tampering,
};

pub const Severity = enum {
    Baixa,
    Alta,
    Grave,
    Critica,

    pub fn rank(self: Severity) u8 {
        return switch (self) {
            .Baixa => 0,
            .Alta => 1,
            .Grave => 2,
            .Critica => 3,
        };
    }

    pub fn parse(s: []const u8) ?Severity {
        if (std.mem.eql(u8, s, "Baixa")) return .Baixa;
        if (std.mem.eql(u8, s, "Alta")) return .Alta;
        if (std.mem.eql(u8, s, "Grave")) return .Grave;
        if (std.mem.eql(u8, s, "Critica")) return .Critica;
        return null;
    }
};

pub fn isHexLower64(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return false;
    }
    return true;
}

pub fn getString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

pub fn getU64(obj: std.json.ObjectMap, key: []const u8) ?u64 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .integer => |n| blk: {
            if (n < 0) return null;
            break :blk std.math.cast(u64, n) orelse return null;
        },
        else => null,
    };
}
