const std = @import("std");
const schema = @import("schema.zig");

const Blake3 = std.crypto.hash.Blake3;

fn hashField(h: *Blake3, tag: []const u8, data: []const u8) void {
    var tlen: [4]u8 = undefined;
    std.mem.writeInt(u32, &tlen, @intCast(tag.len), .little);
    h.update(&tlen);
    h.update(tag);

    var dlen: [4]u8 = undefined;
    std.mem.writeInt(u32, &dlen, @intCast(data.len), .little);
    h.update(&dlen);
    h.update(data);
}

fn pushU64Le(h: *Blake3, v: u64) void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    h.update(&b);
}

pub fn verifyLine(alloc: std.mem.Allocator, line: []const u8) schema.VerifyResult {
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, line, .{}) catch return .SchemaInvalid;
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |o| o,
        else => return .SchemaInvalid,
    };

    const audit_hash_str = schema.getString(root_obj, "audit_hash") orelse return .SchemaInvalid;
    if (!schema.isHexLower64(audit_hash_str)) return .SchemaInvalid;

    const trace_val = root_obj.get("trace") orelse return .SchemaInvalid;
    const trace_arr = switch (trace_val) {
        .array => |a| a,
        else => return .SchemaInvalid,
    };

    _ = schema.getString(root_obj, "request_id") orelse return .SchemaInvalid;
    _ = schema.getString(root_obj, "final_decision") orelse return .SchemaInvalid;

    var hasher = Blake3.init(.{});
    hashField(&hasher, "schema", "trace_v4");

    for (trace_arr.items) |item| {
        switch (item) {
            .string => |s| {
                if (!std.mem.eql(u8, s, "Approved")) return .SchemaInvalid;
                hashField(&hasher, "D:A", "");
            },
            .object => |obj| {
                if (obj.count() != 1) return .SchemaInvalid;
                var it = obj.iterator();
                const one = it.next() orelse return .SchemaInvalid;
                const variant = one.key_ptr.*;
                const payload_obj = switch (one.value_ptr.*) {
                    .object => |o| o,
                    else => return .SchemaInvalid,
                };

                const rule_id = schema.getString(payload_obj, "rule_id") orelse return .SchemaInvalid;
                const reason = schema.getString(payload_obj, "reason") orelse return .SchemaInvalid;
                const sev = schema.getString(payload_obj, "severity") orelse return .SchemaInvalid;
                const severity = schema.Severity.parse(sev) orelse return .SchemaInvalid;
                const measured = schema.getU64(payload_obj, "measured") orelse return .SchemaInvalid;
                const threshold = schema.getU64(payload_obj, "threshold") orelse return .SchemaInvalid;

                if (std.mem.eql(u8, variant, "FlaggedForReview")) {
                    hashField(&hasher, "D:F", rule_id);
                } else if (std.mem.eql(u8, variant, "Blocked")) {
                    hashField(&hasher, "D:B", rule_id);
                } else {
                    return .SchemaInvalid;
                }

                hashField(&hasher, "R", reason);
                hasher.update(&[_]u8{severity.rank()});
                pushU64Le(&hasher, measured);
                pushU64Le(&hasher, threshold);
            },
            else => return .SchemaInvalid,
        }
    }

    var out: [32]u8 = undefined;
    hasher.final(&out);

    var out_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&out_hex, "{s}", .{std.fmt.fmtSliceHexLower(&out)}) catch return .SchemaInvalid;

    if (!std.mem.eql(u8, out_hex[0..], audit_hash_str)) return .Tampering;
    return .Ok;
}

test "verifyLine accepts known-good fixture line" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"julia_bridge_user","amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",{"FlaggedForReview":{"measured":150000,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}],"audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, result);
}

test "verifyLine detects tampering" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"julia_bridge_user","amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",{"FlaggedForReview":{"measured":150001,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}],"audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Tampering, result);
}

test "verifyLine rejects schema drift" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","final_decision":"Flagged","trace":["APPROVED"],"audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}
