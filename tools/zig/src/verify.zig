const std = @import("std");
const schema = @import("schema.zig");
const crypto = @import("crypto.zig");

pub const VerifyOptions = struct {
    allow_legacy_sha3_256: bool = false,
};

fn toHexLower(alloc: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try alloc.alloc(u8, bytes.len * 2);
    errdefer alloc.free(out);
    _ = std.fmt.bufPrint(out, "{s}", .{std.fmt.fmtSliceHexLower(bytes)}) catch return error.FormatFailed;
    return out;
}

fn hashTrace(
    alloc: std.mem.Allocator,
    hash_algo: crypto.HashAlgorithm,
    trace_arr: std.json.Array,
) ![]u8 {
    if (hash_algo.isHybrid()) {
        var shake_hasher = crypto.Hasher.init(.shake256_512);
        crypto.hashField(&shake_hasher, "schema", "trace_v4");
        try hashTraceItems(&shake_hasher, trace_arr);
        const shake_bytes = try shake_hasher.finalAlloc(alloc);
        defer alloc.free(shake_bytes);

        var blake_hasher = crypto.Hasher.init(.blake3_256);
        crypto.hashField(&blake_hasher, "schema", "trace_v4");
        try hashTraceItems(&blake_hasher, trace_arr);
        const blake_bytes = try blake_hasher.finalAlloc(alloc);
        defer alloc.free(blake_bytes);

        const out = try alloc.alloc(u8, shake_bytes.len + blake_bytes.len);
        @memcpy(out[0..shake_bytes.len], shake_bytes);
        @memcpy(out[shake_bytes.len..], blake_bytes);
        return out;
    }

    var hasher = crypto.Hasher.init(hash_algo);
    crypto.hashField(&hasher, "schema", "trace_v4");
    try hashTraceItems(&hasher, trace_arr);
    return hasher.finalAlloc(alloc);
}

fn hashCanonicalBytes(
    alloc: std.mem.Allocator,
    hash_algo: crypto.HashAlgorithm,
    canonical_bytes: []const u8,
) ![]u8 {
    if (hash_algo.isHybrid()) {
        var shake_hasher = crypto.Hasher.init(.shake256_512);
        shake_hasher.update(canonical_bytes);
        const shake_bytes = try shake_hasher.finalAlloc(alloc);
        defer alloc.free(shake_bytes);

        var blake_hasher = crypto.Hasher.init(.blake3_256);
        blake_hasher.update(canonical_bytes);
        const blake_bytes = try blake_hasher.finalAlloc(alloc);
        defer alloc.free(blake_bytes);

        const out = try alloc.alloc(u8, shake_bytes.len + blake_bytes.len);
        @memcpy(out[0..shake_bytes.len], shake_bytes);
        @memcpy(out[shake_bytes.len..], blake_bytes);
        return out;
    }

    var hasher = crypto.Hasher.init(hash_algo);
    hasher.update(canonical_bytes);
    return hasher.finalAlloc(alloc);
}

// Canonicalization note:
// Rust hashes semantic trace entries (schema tag + framed fields), not raw JSON bytes.
// We intentionally mirror that exact ordered framing and never reorder trace entries.
fn hashTraceItems(hasher: *crypto.Hasher, trace_arr: std.json.Array) !void {
    for (trace_arr.items) |item| {
        switch (item) {
            .string => |s| {
                if (!std.mem.eql(u8, s, "Approved")) return error.SchemaInvalid;
                crypto.hashField(hasher, "D:A", "");
            },
            .object => |obj| {
                if (obj.count() != 1) return error.SchemaInvalid;
                var it = obj.iterator();
                const one = it.next() orelse return error.SchemaInvalid;
                const variant = one.key_ptr.*;
                const payload_obj = switch (one.value_ptr.*) {
                    .object => |o| o,
                    else => return error.SchemaInvalid,
                };

                const rule_id = schema.getString(payload_obj, "rule_id") orelse return error.SchemaInvalid;
                const reason = schema.getString(payload_obj, "reason") orelse return error.SchemaInvalid;
                const sev = schema.getString(payload_obj, "severity") orelse return error.SchemaInvalid;
                const severity = schema.Severity.parse(sev) orelse return error.SchemaInvalid;
                const measured = schema.getU64(payload_obj, "measured") orelse return error.SchemaInvalid;
                const threshold = schema.getU64(payload_obj, "threshold") orelse return error.SchemaInvalid;

                if (std.mem.eql(u8, variant, "FlaggedForReview")) {
                    crypto.hashField(hasher, "D:F", rule_id);
                } else if (std.mem.eql(u8, variant, "Blocked")) {
                    crypto.hashField(hasher, "D:B", rule_id);
                } else {
                    return error.SchemaInvalid;
                }

                crypto.hashField(hasher, "R", reason);
                hasher.update(&[_]u8{severity.rank()});
                crypto.pushU64Le(hasher, measured);
                crypto.pushU64Le(hasher, threshold);
            },
            else => return error.SchemaInvalid,
        }
    }
}

pub fn verifyLine(alloc: std.mem.Allocator, line: []const u8) schema.VerifyResult {
    return verifyLineWithOptions(alloc, line, .{});
}

fn parseHashAlgorithm(hash_algo_str: []const u8, options: VerifyOptions) ?crypto.HashAlgorithm {
    if (std.mem.eql(u8, hash_algo_str, "sha3-256")) {
        return if (options.allow_legacy_sha3_256) .sha3_256_legacy else null;
    }
    return crypto.HashAlgorithm.parse(hash_algo_str);
}

pub fn verifyLineWithOptions(
    alloc: std.mem.Allocator,
    line: []const u8,
    options: VerifyOptions,
) schema.VerifyResult {
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, line, .{}) catch return .SchemaInvalid;
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |o| o,
        else => return .SchemaInvalid,
    };

    const audit_hash_str = schema.getString(root_obj, "audit_hash") orelse return .SchemaInvalid;
    const hash_algo_str = schema.getString(root_obj, "hash_algo") orelse return .SchemaInvalid;
    const hash_algo = parseHashAlgorithm(hash_algo_str, options) orelse return .SchemaInvalid;
    if (!schema.isHexLowerN(audit_hash_str, hash_algo.outputLenHex())) return .SchemaInvalid;

    const trace_val = root_obj.get("trace") orelse return .SchemaInvalid;
    const trace_arr = switch (trace_val) {
        .array => |a| a,
        else => return .SchemaInvalid,
    };
    if (trace_arr.items.len == 0) return .SchemaInvalid;

    _ = schema.getString(root_obj, "request_id") orelse return .SchemaInvalid;
    const final_decision = schema.getString(root_obj, "final_decision") orelse return .SchemaInvalid;
    var has_blocked = false;
    var has_flagged = false;

    for (trace_arr.items) |item| {
        switch (item) {
            .string => |s| {
                if (!std.mem.eql(u8, s, "Approved")) return .SchemaInvalid;
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

                _ = schema.getString(payload_obj, "rule_id") orelse return .SchemaInvalid;
                _ = schema.getString(payload_obj, "reason") orelse return .SchemaInvalid;
                const sev = schema.getString(payload_obj, "severity") orelse return .SchemaInvalid;
                _ = schema.Severity.parse(sev) orelse return .SchemaInvalid;
                _ = schema.getU64(payload_obj, "measured") orelse return .SchemaInvalid;
                _ = schema.getU64(payload_obj, "threshold") orelse return .SchemaInvalid;

                if (std.mem.eql(u8, variant, "FlaggedForReview")) {
                    has_flagged = true;
                } else if (std.mem.eql(u8, variant, "Blocked")) {
                    has_blocked = true;
                } else {
                    return .SchemaInvalid;
                }
            },
            else => return .SchemaInvalid,
        }
    }
    const out_bytes = blk: {
        if (schema.getString(root_obj, "trace_bytes")) |trace_bytes_b64| {
            // If producer provides canonical trace_bytes (base64), prefer exact bytes over reconstructed framing.
            const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(trace_bytes_b64) catch return .SchemaInvalid;
            const decoded = alloc.alloc(u8, decoded_len) catch return .SchemaInvalid;
            defer alloc.free(decoded);
            std.base64.standard.Decoder.decode(decoded, trace_bytes_b64) catch return .SchemaInvalid;
            break :blk hashCanonicalBytes(alloc, hash_algo, decoded) catch return .SchemaInvalid;
        }
        break :blk hashTrace(alloc, hash_algo, trace_arr) catch return .SchemaInvalid;
    };
    defer alloc.free(out_bytes);
    const out_hex = toHexLower(alloc, out_bytes) catch return .SchemaInvalid;
    defer alloc.free(out_hex);

    const expected_final = if (has_blocked)
        "Blocked"
    else if (has_flagged)
        "Flagged"
    else
        "Approved";

    if (!std.mem.eql(u8, final_decision, expected_final)) return .SchemaInvalid;
    if (!std.mem.eql(u8, out_hex, audit_hash_str)) return .Tampering;
    return .Ok;
}

const TRACE_FLAGGED_JSON =
    \\["Approved","Approved",{"FlaggedForReview":{"measured":150000,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}]
;

fn readFirstNonEmptyLine(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    const content = try std.fs.cwd().readFileAlloc(alloc, path, 1024 * 1024);
    errdefer alloc.free(content);

    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        return try alloc.dupe(u8, line);
    }
    return error.EmptyFixture;
}

fn buildLineWithComputedHash(
    alloc: std.mem.Allocator,
    request_id: []const u8,
    final_decision: []const u8,
    hash_algo_str: []const u8,
    trace_json: []const u8,
) ![]u8 {
    const hash_algo = parseHashAlgorithm(hash_algo_str, .{
        .allow_legacy_sha3_256 = true,
    }) orelse return error.InvalidHashAlgo;
    var parsed_trace = try std.json.parseFromSlice(std.json.Value, alloc, trace_json, .{});
    defer parsed_trace.deinit();

    const trace_arr = switch (parsed_trace.value) {
        .array => |a| a,
        else => return error.InvalidTrace,
    };

    const bytes = try hashTrace(alloc, hash_algo, trace_arr);
    defer alloc.free(bytes);
    const hex = try toHexLower(alloc, bytes);
    defer alloc.free(hex);

    return try std.fmt.allocPrint(
        alloc,
        "{{\"request_id\":\"{s}\",\"final_decision\":\"{s}\",\"trace\":{s},\"hash_algo\":\"{s}\",\"audit_hash\":\"{s}\"}}",
        .{ request_id, final_decision, trace_json, hash_algo_str, hex },
    );
}

test "verifyLine accepts known-good fixture line" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"julia_bridge_user","amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",{"FlaggedForReview":{"measured":150000,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}],"hash_algo":"blake3-256","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, result);
}

test "verifyLine detects tampering" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"julia_bridge_user","amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",{"FlaggedForReview":{"measured":150001,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}],"hash_algo":"blake3-256","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Tampering, result);
}

test "verifyLine rejects schema drift" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","final_decision":"Flagged","trace":["APPROVED"],"hash_algo":"blake3-256","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine rejects empty trace array as schema invalid" {
    const line =
        \\{"request_id":"empty-trace-001","final_decision":"Approved","trace":[],"hash_algo":"blake3-256","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine rejects uppercase audit hash as schema invalid" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"julia_bridge_user","amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",{"FlaggedForReview":{"measured":150000,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}],"hash_algo":"blake3-256","audit_hash":"BF5CFDA1E218837D2F8A597F8011B4096A38E8578DB23EF6AEEEDE292B4649F3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine accepts blocked fixture line" {
    const line =
        \\{"request_id":"blocked-fixture-001","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1772149279575,"user_id":"zig_fixture_user","amount_cents":150000,"risk_bps":1000,"final_decision":"Blocked","trace":[{"Blocked":{"measured":1,"reason":"UI integrity verification failed.","rule_id":"UI-FRAUD-001","severity":"Critica","threshold":0}},{"Blocked":{"measured":150000,"reason":"Night transaction limit exceeded.","rule_id":"BCB-NIGHT-001","severity":"Grave","threshold":100000}},"Approved"],"hash_algo":"blake3-256","audit_hash":"7f7be4cc47bcb2659ce6b2c857cb64886c433d2c17a6951ab33c6986d47e7131"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, result);
}

test "verifyLine detects tampering on blocked fixture line" {
    const line =
        \\{"request_id":"blocked-fixture-001","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1772149279575,"user_id":"zig_fixture_user","amount_cents":150000,"risk_bps":1000,"final_decision":"Blocked","trace":[{"Blocked":{"measured":1,"reason":"UI integrity verification failed.","rule_id":"UI-FRAUD-001","severity":"Critica","threshold":0}},{"Blocked":{"measured":150001,"reason":"Night transaction limit exceeded.","rule_id":"BCB-NIGHT-001","severity":"Grave","threshold":100000}},"Approved"],"hash_algo":"blake3-256","audit_hash":"7f7be4cc47bcb2659ce6b2c857cb64886c433d2c17a6951ab33c6986d47e7131"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Tampering, result);
}

test "verifyLine rejects missing final_decision" {
    const line =
        \\{"request_id":"missing-final-001","trace":["Approved"],"hash_algo":"blake3-256","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine rejects missing request_id" {
    const line =
        \\{"final_decision":"Approved","trace":["Approved"],"hash_algo":"blake3-256","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine rejects final_decision mismatch when hash matches trace" {
    const line =
        \\{"request_id":"blocked-fixture-001","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1772149279575,"user_id":"zig_fixture_user","amount_cents":150000,"risk_bps":1000,"final_decision":"Approved","trace":[{"Blocked":{"measured":1,"reason":"UI integrity verification failed.","rule_id":"UI-FRAUD-001","severity":"Critica","threshold":0}},{"Blocked":{"measured":150000,"reason":"Night transaction limit exceeded.","rule_id":"BCB-NIGHT-001","severity":"Grave","threshold":100000}},"Approved"],"hash_algo":"blake3-256","audit_hash":"7f7be4cc47bcb2659ce6b2c857cb64886c433d2c17a6951ab33c6986d47e7131"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine accepts legacy blake3 string alias" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"julia_bridge_user","amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",{"FlaggedForReview":{"measured":150000,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}],"hash_algo":"blake3","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, result);
}

test "verifyLine accepts shake256-512 record" {
    const line = try buildLineWithComputedHash(
        std.testing.allocator,
        "shake-fixture-001",
        "Flagged",
        "shake256-512",
        TRACE_FLAGGED_JSON,
    );
    defer std.testing.allocator.free(line);

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, result);
}

test "verifyLine accepts hybrid record and enforces 192 hex chars" {
    const line = try buildLineWithComputedHash(
        std.testing.allocator,
        "hybrid-fixture-001",
        "Flagged",
        "shake256-512+blake3-256",
        TRACE_FLAGGED_JSON,
    );
    defer std.testing.allocator.free(line);

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, result);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, line, .{});
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidRecord,
    };
    const hash = schema.getString(obj, "audit_hash") orelse return error.InvalidRecord;
    try std.testing.expectEqual(@as(usize, 192), hash.len);
}

test "verifyLine rejects unknown hash_algo" {
    const line =
        \\{"request_id":"unknown-hash-001","final_decision":"Approved","trace":["Approved"],"hash_algo":"shake999-999","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine rejects sha3-256 now unsupported in contract" {
    const line =
        \\{"request_id":"d1b13dbd-8ce2-41ea-a2d7-c5294e320fcb","calc_version":null,"profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"julia_bridge_user","amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",{"FlaggedForReview":{"measured":150000,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}],"hash_algo":"sha3-256","audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"}
    ;

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}

test "verifyLine accepts sha3-256 only with legacy support enabled" {
    const line = try buildLineWithComputedHash(
        std.testing.allocator,
        "legacy-sha3-fixture-001",
        "Flagged",
        "sha3-256",
        TRACE_FLAGGED_JSON,
    );
    defer std.testing.allocator.free(line);

    const rejected = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, rejected);

    const accepted = verifyLineWithOptions(std.testing.allocator, line, .{
        .allow_legacy_sha3_256 = true,
    });
    try std.testing.expectEqual(schema.VerifyResult.Ok, accepted);
}

test "verifyLine accepts Rust-generated blake3 fixture file" {
    const line = try readFirstNonEmptyLine(std.testing.allocator, "../../fixtures/audit_rust_blake3.jsonl");
    defer std.testing.allocator.free(line);

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, result);
}

test "verifyLine accepts Rust-generated shake512 fixture file" {
    const line = try readFirstNonEmptyLine(std.testing.allocator, "../../fixtures/audit_rust_shake512.jsonl");
    defer std.testing.allocator.free(line);

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, result);
}

test "verifyLine accepts Rust-generated hybrid fixture file" {
    const line = try readFirstNonEmptyLine(std.testing.allocator, "../../fixtures/audit_rust_hybrid.jsonl");
    defer std.testing.allocator.free(line);

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, result);
}
