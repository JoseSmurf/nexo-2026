const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = std.process.args();
    _ = args.next();
    const path = args.next() orelse {
        std.debug.print("usage: zig run tools/zig/audit_verify.zig -- <audit.jsonl> [line_number]\n", .{});
        return error.InvalidArguments;
    };

    const line_number: usize = if (args.next()) |line_str|
        try std.fmt.parseUnsigned(usize, line_str, 10)
    else
        1;

    const file_data = try std.fs.cwd().readFileAlloc(allocator, path, 16 * 1024 * 1024);
    defer allocator.free(file_data);

    const line = try selectNonEmptyLine(allocator, file_data, line_number);
    defer allocator.free(line);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
    defer parsed.deinit();

    const root = parsed.value;
    const root_obj = switch (root) {
        .object => |o| o,
        else => return error.InvalidJson,
    };

    const trace_value = root_obj.get("trace") orelse return error.MissingTrace;
    const stored_hash_value = root_obj.get("audit_hash") orelse return error.MissingAuditHash;

    const stored_hash = switch (stored_hash_value) {
        .string => |s| s,
        else => return error.InvalidAuditHashType,
    };

    var hasher = Blake3.init(.{});
    hashField(&hasher, "schema", "trace_v4");
    try hashTrace(&hasher, trace_value);

    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    var calc_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&calc_hex, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch unreachable;

    const matched = std.mem.eql(u8, stored_hash, calc_hex[0..]);
    std.debug.print("line={d}\n", .{line_number});
    std.debug.print("stored={s}\n", .{stored_hash});
    std.debug.print("calc  ={s}\n", .{calc_hex});
    std.debug.print("match ={s}\n", .{if (matched) "true" else "false"});

    if (!matched) return error.HashMismatch;
}

fn selectNonEmptyLine(allocator: std.mem.Allocator, content: []const u8, target_line: usize) ![]u8 {
    if (target_line == 0) return error.InvalidLine;

    var it = std.mem.splitScalar(u8, content, '\n');
    var idx: usize = 0;
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        idx += 1;
        if (idx == target_line) return try allocator.dupe(u8, line);
    }
    return error.LineOutOfRange;
}

fn hashField(hasher: *Blake3, tag: []const u8, data: []const u8) void {
    var tag_len_le: [4]u8 = undefined;
    std.mem.writeInt(u32, &tag_len_le, @intCast(tag.len), .little);
    hasher.update(&tag_len_le);
    hasher.update(tag);

    var data_len_le: [4]u8 = undefined;
    std.mem.writeInt(u32, &data_len_le, @intCast(data.len), .little);
    hasher.update(&data_len_le);
    hasher.update(data);
}

fn severityRank(sev: []const u8) !u8 {
    if (std.mem.eql(u8, sev, "Baixa")) return 0;
    if (std.mem.eql(u8, sev, "Alta")) return 1;
    if (std.mem.eql(u8, sev, "Grave")) return 2;
    if (std.mem.eql(u8, sev, "Critica")) return 3;
    return error.InvalidSeverity;
}

fn asU64(v: std.json.Value) !u64 {
    return switch (v) {
        .integer => |n| std.math.cast(u64, n) orelse return error.InvalidIntegerRange,
        else => error.ExpectedInteger,
    };
}

fn hashTrace(hasher: *Blake3, trace_value: std.json.Value) !void {
    const arr = switch (trace_value) {
        .array => |a| a,
        else => return error.TraceMustBeArray,
    };

    for (arr.items) |entry| {
        switch (entry) {
            .string => |s| {
                if (!std.mem.eql(u8, s, "Approved")) return error.UnknownDecisionString;
                hashField(hasher, "D:A", "");
            },
            .object => |obj| {
                if (obj.count() != 1) return error.InvalidDecisionObject;

                if (obj.get("FlaggedForReview")) |flag_v| {
                    const fobj = switch (flag_v) {
                        .object => |o| o,
                        else => return error.InvalidFlaggedPayload,
                    };

                    const rule_id_v = fobj.get("rule_id") orelse return error.MissingRuleId;
                    const reason_v = fobj.get("reason") orelse return error.MissingReason;
                    const severity_v = fobj.get("severity") orelse return error.MissingSeverity;
                    const measured_v = fobj.get("measured") orelse return error.MissingMeasured;
                    const threshold_v = fobj.get("threshold") orelse return error.MissingThreshold;

                    const rule_id = switch (rule_id_v) {
                        .string => |s| s,
                        else => return error.InvalidRuleIdType,
                    };
                    const reason = switch (reason_v) {
                        .string => |s| s,
                        else => return error.InvalidReasonType,
                    };
                    const severity = switch (severity_v) {
                        .string => |s| s,
                        else => return error.InvalidSeverityType,
                    };
                    const measured = try asU64(measured_v);
                    const threshold = try asU64(threshold_v);

                    hashField(hasher, "D:F", rule_id);
                    hashField(hasher, "R", reason);

                    const rank = try severityRank(severity);
                    hasher.update(&[_]u8{rank});

                    var measured_le: [8]u8 = undefined;
                    std.mem.writeInt(u64, &measured_le, measured, .little);
                    hasher.update(&measured_le);

                    var threshold_le: [8]u8 = undefined;
                    std.mem.writeInt(u64, &threshold_le, threshold, .little);
                    hasher.update(&threshold_le);
                    continue;
                }

                if (obj.get("Blocked")) |blocked_v| {
                    const bobj = switch (blocked_v) {
                        .object => |o| o,
                        else => return error.InvalidBlockedPayload,
                    };

                    const rule_id_v = bobj.get("rule_id") orelse return error.MissingRuleId;
                    const reason_v = bobj.get("reason") orelse return error.MissingReason;
                    const severity_v = bobj.get("severity") orelse return error.MissingSeverity;
                    const measured_v = bobj.get("measured") orelse return error.MissingMeasured;
                    const threshold_v = bobj.get("threshold") orelse return error.MissingThreshold;

                    const rule_id = switch (rule_id_v) {
                        .string => |s| s,
                        else => return error.InvalidRuleIdType,
                    };
                    const reason = switch (reason_v) {
                        .string => |s| s,
                        else => return error.InvalidReasonType,
                    };
                    const severity = switch (severity_v) {
                        .string => |s| s,
                        else => return error.InvalidSeverityType,
                    };
                    const measured = try asU64(measured_v);
                    const threshold = try asU64(threshold_v);

                    hashField(hasher, "D:B", rule_id);
                    hashField(hasher, "R", reason);

                    const rank = try severityRank(severity);
                    hasher.update(&[_]u8{rank});

                    var measured_le: [8]u8 = undefined;
                    std.mem.writeInt(u64, &measured_le, measured, .little);
                    hasher.update(&measured_le);

                    var threshold_le: [8]u8 = undefined;
                    std.mem.writeInt(u64, &threshold_le, threshold, .little);
                    hasher.update(&threshold_le);
                    continue;
                }

                return error.UnknownDecisionKind;
            },
            else => return error.InvalidTraceEntry,
        }
    }
}
