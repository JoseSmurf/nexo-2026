const std = @import("std");
const schema = @import("schema.zig");
const crypto = @import("crypto.zig");

pub const VerifyOptions = struct {
    allow_legacy_sha3_256: bool = false,
};

pub const RequireChainState = struct {
    prev_record_hash: ?[]u8 = null,
    have_prev_record_hash: bool = false,

    pub fn deinit(self: *RequireChainState, alloc: std.mem.Allocator) void {
        if (self.prev_record_hash) |buf| alloc.free(buf);
        self.prev_record_hash = null;
        self.have_prev_record_hash = false;
    }
};

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

fn stringifyJsonMinifiedAlloc(alloc: std.mem.Allocator, v: std.json.Value) ![]const u8 {
    if (@hasDecl(std.json, "stringifyAlloc")) {
        return std.json.stringifyAlloc(alloc, v, .{ .whitespace = .minified });
    }
    return std.json.Stringify.valueAlloc(alloc, v, .{ .whitespace = .minified });
}

// Internal helper for record_hash validation:
// Mirrors Rust `src/audit/record.rs::compute_record_hash` (schema: audit_record_v2).
// Wired into verify only when `record_hash` is present and non-null.
fn computeRecordHashV2Hex(alloc: std.mem.Allocator, root_obj: std.json.ObjectMap) ![]u8 {
    var hasher = crypto.Hasher.init(.blake3);

    const request_id = schema.getString(root_obj, "request_id") orelse return error.SchemaInvalid;
    const profile_name = schema.getString(root_obj, "profile_name") orelse return error.SchemaInvalid;
    const profile_version = schema.getString(root_obj, "profile_version") orelse return error.SchemaInvalid;
    const calc_version = schema.getStringOrEmpty(root_obj, "calc_version") orelse return error.SchemaInvalid;
    const user_id = schema.getString(root_obj, "user_id") orelse return error.SchemaInvalid;
    const audit_hash_str = schema.getString(root_obj, "audit_hash") orelse return error.SchemaInvalid;
    const hash_algo_str = schema.getString(root_obj, "hash_algo") orelse return error.SchemaInvalid;
    const sha3_shadow = schema.getStringOrEmpty(root_obj, "sha3_shadow") orelse return error.SchemaInvalid;
    const final_decision = schema.getString(root_obj, "final_decision") orelse return error.SchemaInvalid;
    const prev_record_hash = schema.getStringOrEmpty(root_obj, "prev_record_hash") orelse return error.SchemaInvalid;

    const timestamp_utc_ms = schema.getU64(root_obj, "timestamp_utc_ms") orelse return error.SchemaInvalid;
    const amount_cents = schema.getU64(root_obj, "amount_cents") orelse return error.SchemaInvalid;
    const risk_bps_u64 = schema.getU64(root_obj, "risk_bps") orelse return error.SchemaInvalid;
    const risk_bps = std.math.cast(u16, risk_bps_u64) orelse return error.SchemaInvalid;

    const trace_val = root_obj.get("trace") orelse return error.SchemaInvalid;
    var trace_json_alloc: ?[]const u8 = null;
    const trace_json: []const u8 = blk: {
        const s = stringifyJsonMinifiedAlloc(alloc, trace_val) catch break :blk "[]";
        trace_json_alloc = s;
        break :blk s;
    };
    defer if (trace_json_alloc) |s| alloc.free(s);

    crypto.hashField(&hasher, "schema", "audit_record_v2");
    crypto.hashField(&hasher, "request_id", request_id);
    crypto.hashField(&hasher, "profile_name", profile_name);
    crypto.hashField(&hasher, "profile_version", profile_version);
    crypto.hashField(&hasher, "calc_version", calc_version);
    crypto.hashField(&hasher, "user_id", user_id);
    crypto.hashField(&hasher, "audit_hash", audit_hash_str);
    crypto.hashField(&hasher, "hash_algo", hash_algo_str);
    crypto.hashField(&hasher, "sha3_shadow", sha3_shadow);
    crypto.hashField(&hasher, "final_decision", final_decision);
    crypto.hashField(&hasher, "trace_json", trace_json);
    crypto.hashField(&hasher, "prev_record_hash", prev_record_hash);
    crypto.pushU64Le(&hasher, timestamp_utc_ms);
    crypto.pushU64Le(&hasher, amount_cents);
    crypto.pushU16Le(&hasher, risk_bps);

    const out_bytes = try hasher.finalAlloc(alloc);
    defer alloc.free(out_bytes);
    return try toHexLower(alloc, out_bytes);
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
    const out_bytes_from_trace = hashTrace(alloc, hash_algo, trace_arr) catch return .SchemaInvalid;
    defer alloc.free(out_bytes_from_trace);

    var out_bytes = out_bytes_from_trace;
    if (schema.getString(root_obj, "trace_bytes")) |trace_bytes_b64| {
        // When trace_bytes is present, require it to match the semantic trace framing.
        // This prevents accepting records where trace JSON diverges from canonical bytes.
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(trace_bytes_b64) catch return .SchemaInvalid;
        const decoded = alloc.alloc(u8, decoded_len) catch return .SchemaInvalid;
        defer alloc.free(decoded);
        std.base64.standard.Decoder.decode(decoded, trace_bytes_b64) catch return .SchemaInvalid;

        const out_bytes_from_trace_bytes = hashCanonicalBytes(alloc, hash_algo, decoded) catch return .SchemaInvalid;
        defer alloc.free(out_bytes_from_trace_bytes);
        if (!std.mem.eql(u8, out_bytes_from_trace, out_bytes_from_trace_bytes)) return .SchemaInvalid;
        out_bytes = out_bytes_from_trace_bytes;
    }
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

    // Optional record_hash integrity check:
    // - absent/null => do not enforce (legacy fixtures remain valid)
    // - string => must match recomputed `audit_record_v2` framing
    if (root_obj.get("record_hash")) |record_hash_val| {
        switch (record_hash_val) {
            .null => {},
            .string => |record_hash_str| {
                if (!schema.isHexLowerN(record_hash_str, 64)) return .SchemaInvalid;
                const computed_record_hash = computeRecordHashV2Hex(alloc, root_obj) catch return .SchemaInvalid;
                defer alloc.free(computed_record_hash);
                if (!std.mem.eql(u8, computed_record_hash, record_hash_str)) return .Tampering;
            },
            else => return .SchemaInvalid,
        }
    }
    return .Ok;
}

pub fn verifyLineWithOptionsRequireChain(
    alloc: std.mem.Allocator,
    line: []const u8,
    options: VerifyOptions,
    state: *RequireChainState,
) schema.VerifyResult {
    const base = verifyLineWithOptions(alloc, line, options);

    // Parse only what's needed for chain continuity checks.
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, line, .{}) catch return .SchemaInvalid;
    defer parsed.deinit();
    const root_obj = switch (parsed.value) {
        .object => |o| o,
        else => return .SchemaInvalid,
    };

    // In chain-required mode, record_hash must exist and be a valid lowercase hex string.
    const record_hash_val = root_obj.get("record_hash") orelse return .SchemaInvalid;
    const record_hash_str = switch (record_hash_val) {
        .string => |s| s,
        else => return .SchemaInvalid,
    };
    if (!schema.isHexLowerN(record_hash_str, 64)) return .SchemaInvalid;

    // prev_record_hash validation:
    // - first record: allow missing/null/string (but if string is present, require valid hex format)
    // - subsequent records: require string hex and equal to previous record_hash in this file
    const prev_val_opt = root_obj.get("prev_record_hash");
    if (!state.have_prev_record_hash) {
        if (prev_val_opt) |prev_val| {
            switch (prev_val) {
                .null => {},
                .string => |prev_str| {
                    if (!schema.isHexLowerN(prev_str, 64)) return .SchemaInvalid;
                },
                else => return .SchemaInvalid,
            }
        }
    } else {
        const prev_val = prev_val_opt orelse return .SchemaInvalid;
        const prev_str = switch (prev_val) {
            .string => |s| s,
            else => return .SchemaInvalid,
        };
        if (!schema.isHexLowerN(prev_str, 64)) return .SchemaInvalid;
        const expected_prev = state.prev_record_hash orelse return .SchemaInvalid;
        if (!std.mem.eql(u8, prev_str, expected_prev)) return .Tampering;
    }

    // Only advance chain state when the record is otherwise OK.
    if (base == .Ok) {
        if (state.prev_record_hash) |buf| alloc.free(buf);
        state.prev_record_hash = alloc.dupe(u8, record_hash_str) catch return .SchemaInvalid;
        state.have_prev_record_hash = true;
    }
    return base;
}

const TRACE_FLAGGED_JSON =
    \\["Approved","Approved",{"FlaggedForReview":{"measured":150000,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}]
;

fn readFirstNonEmptyLine(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    const content = try readFileAllocCompat(alloc, path, 1024 * 1024);
    defer alloc.free(content);

    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        return try alloc.dupe(u8, line);
    }
    return error.EmptyFixture;
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

fn objectMapPutCompat(
    obj: *std.json.ObjectMap,
    alloc: std.mem.Allocator,
    key: []const u8,
    value: std.json.Value,
) !void {
    if (@hasDecl(std, "Io")) {
        try obj.put(alloc, key, value);
    } else {
        try obj.put(key, value);
    }
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

    // Golden compatibility check for future record_hash validation.
    // This does not change the public `verifyLine` behavior; it only proves we can
    // recompute Rust's `compute_record_hash` framing in Zig deterministically.
    const record_fixture_line =
        \\{"request_id":"known-request-001","calc_version":"fixture_rust_v1","profile_name":"br_default_v1","profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"rust_fixture_user","amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",{"FlaggedForReview":{"measured":150000,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001","severity":"Alta","threshold":5000000}}],"audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3","hash_algo":"blake3","sha3_shadow":null,"prev_record_hash":null,"record_hash":null}
    ;

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, record_fixture_line, .{});
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidFixture,
    };

    const record_hex = try computeRecordHashV2Hex(std.testing.allocator, obj);
    defer std.testing.allocator.free(record_hex);
    try std.testing.expectEqualStrings(
        "fa75306f29d04f6aafcec77d7dfceb7b44386284e87df8b8c51f5071d01d663f",
        record_hex,
    );

    // Step 2: record_hash is enforced only when present and non-null.
    // - `record_hash: null` remains valid
    // - correct record_hash passes
    // - changing a non-trace field while keeping record_hash fails as tampering
    // - invalid record_hash format fails as schema invalid
    const ok_null = verifyLine(std.testing.allocator, record_fixture_line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, ok_null);

    var with_record_hash = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, record_fixture_line, .{});
    defer with_record_hash.deinit();
    const with_obj = switch (with_record_hash.value) {
        .object => |*o| o,
        else => return error.InvalidFixture,
    };
    try objectMapPutCompat(with_obj, with_record_hash.arena.allocator(), "record_hash", std.json.Value{ .string = record_hex });
    const with_line = try stringifyJsonMinifiedAlloc(std.testing.allocator, with_record_hash.value);
    defer std.testing.allocator.free(with_line);
    const ok_with = verifyLine(std.testing.allocator, with_line);
    try std.testing.expectEqual(schema.VerifyResult.Ok, ok_with);

    try objectMapPutCompat(with_obj, with_record_hash.arena.allocator(), "amount_cents", std.json.Value{ .integer = @as(i64, 150001) });
    const tampered_line = try stringifyJsonMinifiedAlloc(std.testing.allocator, with_record_hash.value);
    defer std.testing.allocator.free(tampered_line);
    const tampered = verifyLine(std.testing.allocator, tampered_line);
    try std.testing.expectEqual(schema.VerifyResult.Tampering, tampered);

    var bad_record_hash = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, record_fixture_line, .{});
    defer bad_record_hash.deinit();
    const bad_obj = switch (bad_record_hash.value) {
        .object => |*o| o,
        else => return error.InvalidFixture,
    };
    try objectMapPutCompat(bad_obj, bad_record_hash.arena.allocator(), "record_hash", std.json.Value{ .string = "ABC" });
    const bad_line = try stringifyJsonMinifiedAlloc(std.testing.allocator, bad_record_hash.value);
    defer std.testing.allocator.free(bad_line);
    const bad = verifyLine(std.testing.allocator, bad_line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, bad);

    // Step 3: optional chain continuity validation (prev_record_hash -> record_hash),
    // enabled only via a separate mode/flag.
    // 2) require-chain rejects record_hash: null
    {
        var chain_state = RequireChainState{};
        defer chain_state.deinit(std.testing.allocator);
        const rejected = verifyLineWithOptionsRequireChain(std.testing.allocator, record_fixture_line, .{}, &chain_state);
        try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, rejected);
    }

    // Build a minimal 2-line artifact with internal continuity:
    // line1.record_hash -> line2.prev_record_hash.
    var line1_record = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, record_fixture_line, .{});
    defer line1_record.deinit();
    const line1_obj = switch (line1_record.value) {
        .object => |*o| o,
        else => return error.InvalidFixture,
    };
    try objectMapPutCompat(line1_obj, line1_record.arena.allocator(), "record_hash", std.json.Value{ .string = record_hex });
    const line1 = try stringifyJsonMinifiedAlloc(std.testing.allocator, line1_record.value);
    defer std.testing.allocator.free(line1);

    var line2_record = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, record_fixture_line, .{});
    defer line2_record.deinit();
    const line2_obj = switch (line2_record.value) {
        .object => |*o| o,
        else => return error.InvalidFixture,
    };
    try objectMapPutCompat(line2_obj, line2_record.arena.allocator(), "request_id", std.json.Value{ .string = "known-request-002" });
    try objectMapPutCompat(line2_obj, line2_record.arena.allocator(), "prev_record_hash", std.json.Value{ .string = record_hex });
    const line2_record_hex = try computeRecordHashV2Hex(std.testing.allocator, line2_obj.*);
    defer std.testing.allocator.free(line2_record_hex);
    try objectMapPutCompat(line2_obj, line2_record.arena.allocator(), "record_hash", std.json.Value{ .string = line2_record_hex });
    const line2 = try stringifyJsonMinifiedAlloc(std.testing.allocator, line2_record.value);
    defer std.testing.allocator.free(line2);

    // 3) 2-line artifact with correct continuity passes in chain mode
    {
        var chain_state = RequireChainState{};
        defer chain_state.deinit(std.testing.allocator);
        const r1 = verifyLineWithOptionsRequireChain(std.testing.allocator, line1, .{}, &chain_state);
        try std.testing.expectEqual(schema.VerifyResult.Ok, r1);
        const r2 = verifyLineWithOptionsRequireChain(std.testing.allocator, line2, .{}, &chain_state);
        try std.testing.expectEqual(schema.VerifyResult.Ok, r2);
    }

    // 4) wrong prev_record_hash in second record fails as tampering (continuity break)
    {
        var wrong_prev = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, line2, .{});
        defer wrong_prev.deinit();
        const wrong_obj = switch (wrong_prev.value) {
            .object => |*o| o,
            else => return error.InvalidFixture,
        };
        // Keep record_hash consistent with this record; only continuity should fail.
        try objectMapPutCompat(wrong_obj, wrong_prev.arena.allocator(), "prev_record_hash", std.json.Value{ .string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
        const recomputed = try computeRecordHashV2Hex(std.testing.allocator, wrong_obj.*);
        defer std.testing.allocator.free(recomputed);
        try objectMapPutCompat(wrong_obj, wrong_prev.arena.allocator(), "record_hash", std.json.Value{ .string = recomputed });
        const wrong_line2 = try stringifyJsonMinifiedAlloc(std.testing.allocator, wrong_prev.value);
        defer std.testing.allocator.free(wrong_line2);

        var chain_state = RequireChainState{};
        defer chain_state.deinit(std.testing.allocator);
        const r1 = verifyLineWithOptionsRequireChain(std.testing.allocator, line1, .{}, &chain_state);
        try std.testing.expectEqual(schema.VerifyResult.Ok, r1);
        const r2 = verifyLineWithOptionsRequireChain(std.testing.allocator, wrong_line2, .{}, &chain_state);
        try std.testing.expectEqual(schema.VerifyResult.Tampering, r2);
    }

    // 5) changing a non-trace field while keeping record_hash old fails as tampering
    {
        var tamper = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, line2, .{});
        defer tamper.deinit();
        const tamper_obj = switch (tamper.value) {
            .object => |*o| o,
            else => return error.InvalidFixture,
        };
        try objectMapPutCompat(tamper_obj, tamper.arena.allocator(), "amount_cents", std.json.Value{ .integer = @as(i64, 150002) });
        const tamper_line2 = try stringifyJsonMinifiedAlloc(std.testing.allocator, tamper.value);
        defer std.testing.allocator.free(tamper_line2);

        var chain_state = RequireChainState{};
        defer chain_state.deinit(std.testing.allocator);
        const r1 = verifyLineWithOptionsRequireChain(std.testing.allocator, line1, .{}, &chain_state);
        try std.testing.expectEqual(schema.VerifyResult.Ok, r1);
        const r2 = verifyLineWithOptionsRequireChain(std.testing.allocator, tamper_line2, .{}, &chain_state);
        try std.testing.expectEqual(schema.VerifyResult.Tampering, r2);
    }

    // 6) invalid prev_record_hash format in second record fails as schema invalid
    {
        var bad_prev = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, line2, .{});
        defer bad_prev.deinit();
        const bad_prev_obj = switch (bad_prev.value) {
            .object => |*o| o,
            else => return error.InvalidFixture,
        };
        try objectMapPutCompat(bad_prev_obj, bad_prev.arena.allocator(), "prev_record_hash", std.json.Value{ .string = "ABC" });
        const bad_prev_line2 = try stringifyJsonMinifiedAlloc(std.testing.allocator, bad_prev.value);
        defer std.testing.allocator.free(bad_prev_line2);

        var chain_state = RequireChainState{};
        defer chain_state.deinit(std.testing.allocator);
        const r1 = verifyLineWithOptionsRequireChain(std.testing.allocator, line1, .{}, &chain_state);
        try std.testing.expectEqual(schema.VerifyResult.Ok, r1);
        const r2 = verifyLineWithOptionsRequireChain(std.testing.allocator, bad_prev_line2, .{}, &chain_state);
        try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, r2);
    }
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

test "all Rust-generated fixture artifacts remain verifiable" {
    const fixture_paths = [_][]const u8{
        "../../fixtures/audit_rust_blake3.jsonl",
        "../../fixtures/audit_rust_shake512.jsonl",
        "../../fixtures/audit_rust_hybrid.jsonl",
    };

    for (fixture_paths) |path| {
        const line = try readFirstNonEmptyLine(std.testing.allocator, path);
        defer std.testing.allocator.free(line);

        const result = verifyLine(std.testing.allocator, line);
        try std.testing.expectEqual(schema.VerifyResult.Ok, result);
    }
}

test "verifyLine rejects diverging trace and trace_bytes" {
    const canonical = "evil-canonical-bytes";
    const hash_bytes = try hashCanonicalBytes(std.testing.allocator, .blake3_256, canonical);
    defer std.testing.allocator.free(hash_bytes);
    const hash_hex = try toHexLower(std.testing.allocator, hash_bytes);
    defer std.testing.allocator.free(hash_hex);

    const b64_len = std.base64.standard.Encoder.calcSize(canonical.len);
    const trace_b64 = try std.testing.allocator.alloc(u8, b64_len);
    defer std.testing.allocator.free(trace_b64);
    _ = std.base64.standard.Encoder.encode(trace_b64, canonical);

    const line = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"request_id\":\"diverge-001\",\"final_decision\":\"Flagged\",\"trace\":{s},\"trace_bytes\":\"{s}\",\"hash_algo\":\"blake3-256\",\"audit_hash\":\"{s}\"}}",
        .{ TRACE_FLAGGED_JSON, trace_b64, hash_hex },
    );
    defer std.testing.allocator.free(line);

    const result = verifyLine(std.testing.allocator, line);
    try std.testing.expectEqual(schema.VerifyResult.SchemaInvalid, result);
}
