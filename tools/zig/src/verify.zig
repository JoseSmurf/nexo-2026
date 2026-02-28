const std = @import("std");
const schema = @import("schema.zig");
const crypto = @import("crypto.zig");

pub fn verifyLine(alloc: std.mem.Allocator, line: []const u8) schema.VerifyResult {
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, line, .{}) catch return .SchemaInvalid;
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |o| o,
        else => return .SchemaInvalid,
    };

    const audit_hash_str = schema.getString(root_obj, "audit_hash") orelse return .SchemaInvalid;
    if (!schema.isHexLower64(audit_hash_str)) return .SchemaInvalid;

    const hash_algo_str = schema.getString(root_obj, "hash_algo") orelse return .SchemaInvalid;
    const hash_algo = crypto.HashAlgorithm.parse(hash_algo_str) orelse return .SchemaInvalid;

    const trace_val = root_obj.get("trace") orelse return .SchemaInvalid;
    const trace_arr = switch (trace_val) {
        .array => |a| a,
        else => return .SchemaInvalid,
    };
    if (trace_arr.items.len == 0) return .SchemaInvalid;

    _ = schema.getString(root_obj, "request_id") orelse return .SchemaInvalid;
    const final_decision = schema.getString(root_obj, "final_decision") orelse return .SchemaInvalid;

    var hasher = crypto.Hasher.init(hash_algo);
    crypto.hashField(&hasher, "schema", "trace_v4");
    var has_blocked = false;
    var has_flagged = false;

    for (trace_arr.items) |item| {
        switch (item) {
            .string => |s| {
                if (!std.mem.eql(u8, s, "Approved")) return .SchemaInvalid;
                crypto.hashField(&hasher, "D:A", "");
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
                    has_flagged = true;
                    crypto.hashField(&hasher, "D:F", rule_id);
                } else if (std.mem.eql(u8, variant, "Blocked")) {
                    has_blocked = true;
                    crypto.hashField(&hasher, "D:B", rule_id);
                } else {
                    return .SchemaInvalid;
                }

                crypto.hashField(&hasher, "R", reason);
                hasher.update(&[_]u8{severity.rank()});
                crypto.pushU64Le(&hasher, measured);
                crypto.pushU64Le(&hasher, threshold);
            },
            else => return .SchemaInvalid,
        }
    }

    var out: [32]u8 = undefined;
    hasher.final(&out);

    var out_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&out_hex, "{s}", .{std.fmt.fmtSliceHexLower(&out)}) catch return .SchemaInvalid;

    const expected_final = if (has_blocked)
        "Blocked"
    else if (has_flagged)
        "Flagged"
    else
        "Approved";

    if (!std.mem.eql(u8, final_decision, expected_final)) return .SchemaInvalid;
    if (!std.mem.eql(u8, out_hex[0..], audit_hash_str)) return .Tampering;
    return .Ok;
}

test "verifyLine accepts known-good fixture line" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"julia_bridge_user","amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",{"FlaggedForReview":{"measured":150000,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}],"hash_algo":"blake3","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, result);
}

test "verifyLine detects tampering" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"julia_bridge_user","amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",{"FlaggedForReview":{"measured":150001,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}],"hash_algo":"blake3","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Tampering, result);
}

test "verifyLine rejects schema drift" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","final_decision":"Flagged","trace":["APPROVED"],"hash_algo":"blake3","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine rejects empty trace array as schema invalid" {
    const line =
        \\{"request_id":"empty-trace-001","final_decision":"Approved","trace":[],"hash_algo":"blake3","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine rejects uppercase audit hash as schema invalid" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"julia_bridge_user","amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",{"FlaggedForReview":{"measured":150000,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}],"hash_algo":"blake3","audit_hash":"BF5CFDA1E218837D2F8A597F8011B4096A38E8578DB23EF6AEEEDE292B4649F3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine accepts blocked fixture line" {
    const line =
        \\{"request_id":"blocked-fixture-001","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1772149279575,"user_id":"zig_fixture_user","amount_cents":150000,"risk_bps":1000,"final_decision":"Blocked","trace":[{"Blocked":{"measured":1,"reason":"UI integrity verification failed.","rule_id":"UI-FRAUD-001","severity":"Critica","threshold":0}},{"Blocked":{"measured":150000,"reason":"Night transaction limit exceeded.","rule_id":"BCB-NIGHT-001","severity":"Grave","threshold":100000}},"Approved"],"hash_algo":"blake3","audit_hash":"7f7be4cc47bcb2659ce6b2c857cb64886c433d2c17a6951ab33c6986d47e7131"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, result);
}

test "verifyLine detects tampering on blocked fixture line" {
    const line =
        \\{"request_id":"blocked-fixture-001","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1772149279575,"user_id":"zig_fixture_user","amount_cents":150000,"risk_bps":1000,"final_decision":"Blocked","trace":[{"Blocked":{"measured":1,"reason":"UI integrity verification failed.","rule_id":"UI-FRAUD-001","severity":"Critica","threshold":0}},{"Blocked":{"measured":150001,"reason":"Night transaction limit exceeded.","rule_id":"BCB-NIGHT-001","severity":"Grave","threshold":100000}},"Approved"],"hash_algo":"blake3","audit_hash":"7f7be4cc47bcb2659ce6b2c857cb64886c433d2c17a6951ab33c6986d47e7131"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Tampering, result);
}

test "verifyLine rejects missing final_decision" {
    const line =
        \\{"request_id":"missing-final-001","trace":["Approved"],"hash_algo":"blake3","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine rejects missing request_id" {
    const line =
        \\{"final_decision":"Approved","trace":["Approved"],"hash_algo":"blake3","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine rejects final_decision mismatch when hash matches trace" {
    const line =
        \\{"request_id":"blocked-fixture-001","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1772149279575,"user_id":"zig_fixture_user","amount_cents":150000,"risk_bps":1000,"final_decision":"Approved","trace":[{"Blocked":{"measured":1,"reason":"UI integrity verification failed.","rule_id":"UI-FRAUD-001","severity":"Critica","threshold":0}},{"Blocked":{"measured":150000,"reason":"Night transaction limit exceeded.","rule_id":"BCB-NIGHT-001","severity":"Grave","threshold":100000}},"Approved"],"hash_algo":"blake3","audit_hash":"7f7be4cc47bcb2659ce6b2c857cb64886c433d2c17a6951ab33c6986d47e7131"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine accepts sha3 algo and detects hash mismatch as tampering" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"julia_bridge_user","amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",{"FlaggedForReview":{"measured":150000,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}],"hash_algo":"sha3-256","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Tampering, result);
}
