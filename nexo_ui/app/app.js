(function () {
  "use strict";

  const state = {
    generatedResponse: null,
    loadedArtifact: null,
    auditView: null,
  };

  const nodes = {
    generateForm: document.getElementById("generate-form"),
    generateOutput: document.getElementById("generate-output"),
    verifyBtn: document.getElementById("verify-btn"),
    verifyOutput: document.getElementById("verify-output"),
    artifactFile: document.getElementById("artifact-file"),
    exportBtn: document.getElementById("export-btn"),
    auditOutput: document.getElementById("audit-output"),
    auditRequestId: document.getElementById("audit-request-id"),
    auditFinalDecision: document.getElementById("audit-final-decision"),
    auditHash: document.getElementById("audit-hash"),
    auditHashAlgo: document.getElementById("audit-hash-algo"),
    auditRecordHash: document.getElementById("audit-record-hash"),
    auditPrevRecordHash: document.getElementById("audit-prev-record-hash"),
    auditProfileName: document.getElementById("audit-profile-name"),
    auditProfileVersion: document.getElementById("audit-profile-version"),
  };

  function nowMs() {
    return Date.now().toString();
  }

  function randomUuidFallback() {
    if (typeof crypto !== "undefined" && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    return "00000000-0000-4000-8000-000000000000";
  }

  function setDefaults() {
    const requestIdInput = document.getElementById("x_request_id");
    const timestampInput = document.getElementById("x_timestamp");
    const txTimestampInput = document.getElementById("tx_timestamp_utc_ms");
    if (requestIdInput && !requestIdInput.value) {
      requestIdInput.value = randomUuidFallback();
    }
    if (timestampInput && !timestampInput.value) {
      timestampInput.value = nowMs();
    }
    if (txTimestampInput && !txTimestampInput.value) {
      txTimestampInput.value = nowMs();
    }
  }

  function asBool(inputId) {
    const el = document.getElementById(inputId);
    return !!(el && el.checked);
  }

  function asValue(inputId) {
    const el = document.getElementById(inputId);
    return el ? el.value : "";
  }

  function readGeneratePayload() {
    return {
      user_id: asValue("user_id").trim(),
      amount_cents: Number(asValue("amount_cents")),
      is_pep: asBool("is_pep"),
      has_active_kyc: asBool("has_active_kyc"),
      timestamp_utc_ms: Number(asValue("tx_timestamp_utc_ms")),
      risk_bps: Number(asValue("risk_bps")),
      ui_hash_valid: asBool("ui_hash_valid"),
      request_id: asValue("x_request_id").trim(),
    };
  }

  function readSignatureHeaders() {
    return {
      "content-type": "application/json",
      "x-key-id": asValue("x_key_id").trim(),
      "x-request-id": asValue("x_request_id").trim(),
      "x-timestamp": asValue("x_timestamp").trim(),
      "x-signature": asValue("x_signature").trim(),
    };
  }

  function setText(node, value) {
    if (node) {
      node.textContent = value;
    }
  }

  function extractAuditView(obj) {
    if (!obj || typeof obj !== "object") {
      return null;
    }
    return {
      request_id: obj.request_id || "n/a",
      final_decision: obj.final_decision || "n/a",
      audit_hash: obj.audit_hash || "n/a",
      hash_algo: obj.hash_algo || "n/a",
      record_hash: obj.record_hash || "not available in /evaluate response",
      prev_record_hash: obj.prev_record_hash || "not available in /evaluate response",
      profile_name: obj.profile_name || "n/a",
      profile_version: obj.profile_version || "n/a",
    };
  }

  function renderAuditView(audit) {
    if (!audit) {
      return;
    }
    state.auditView = audit;
    setText(nodes.auditRequestId, String(audit.request_id));
    setText(nodes.auditFinalDecision, String(audit.final_decision));
    setText(nodes.auditHash, String(audit.audit_hash));
    setText(nodes.auditHashAlgo, String(audit.hash_algo));
    setText(nodes.auditRecordHash, String(audit.record_hash));
    setText(nodes.auditPrevRecordHash, String(audit.prev_record_hash));
    setText(nodes.auditProfileName, String(audit.profile_name));
    setText(nodes.auditProfileVersion, String(audit.profile_version));
    setText(nodes.auditOutput, "Audit panel updated from latest response/artifact.");
  }

  async function handleGenerate(event) {
    event.preventDefault();
    const payload = readGeneratePayload();
    const headers = readSignatureHeaders();

    nodes.generateOutput.className = "output";
    setText(nodes.generateOutput, "Submitting signed /evaluate request...");

    try {
      const response = await fetch("/evaluate", {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      });
      const bodyText = await response.text();
      let json = null;
      try {
        json = JSON.parse(bodyText);
      } catch (_err) {
        json = { raw_body: bodyText };
      }

      state.generatedResponse = {
        http_status: response.status,
        headers: {
          "x-response-signature": response.headers.get("x-response-signature"),
          "x-response-key-id": response.headers.get("x-response-key-id"),
        },
        body: json,
      };

      const pretty = JSON.stringify(state.generatedResponse, null, 2);
      setText(nodes.generateOutput, pretty);
      nodes.generateOutput.classList.add(response.ok ? "ok" : "error");

      if (json && typeof json === "object" && response.ok) {
        const audit = extractAuditView(json);
        renderAuditView(audit);
      }
    } catch (err) {
      setText(nodes.generateOutput, `Request failed: ${String(err)}`);
      nodes.generateOutput.classList.add("error");
    }
  }

  function parseArtifactInput(raw) {
    const text = raw.trim();
    if (!text) {
      throw new Error("empty file");
    }
    if (text.startsWith("{")) {
      return JSON.parse(text);
    }
    const lines = text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    if (lines.length === 0) {
      throw new Error("no non-empty JSONL lines");
    }
    return JSON.parse(lines[lines.length - 1]);
  }

  function hasHex(str, minLen) {
    return typeof str === "string" && str.length >= minLen && /^[0-9a-f]+$/.test(str);
  }

  function traceDecisionHints(trace) {
    if (!Array.isArray(trace)) {
      return { hasBlocked: false, hasFlagged: false };
    }
    let hasBlocked = false;
    let hasFlagged = false;
    for (const item of trace) {
      if (item && typeof item === "object" && !Array.isArray(item)) {
        if (Object.prototype.hasOwnProperty.call(item, "Blocked")) {
          hasBlocked = true;
        }
        if (Object.prototype.hasOwnProperty.call(item, "FlaggedForReview")) {
          hasFlagged = true;
        }
      }
    }
    return { hasBlocked, hasFlagged };
  }

  function sanityCheckArtifact(obj) {
    const errors = [];
    const warnings = [];
    const required = [
      "request_id",
      "final_decision",
      "trace",
      "audit_hash",
      "hash_algo",
      "profile_name",
      "profile_version",
    ];
    for (const field of required) {
      if (!(field in obj)) {
        errors.push(`missing field: ${field}`);
      }
    }
    if (!Array.isArray(obj.trace)) {
      errors.push("trace must be an array");
    } else if (obj.trace.length === 0) {
      errors.push("trace must not be empty");
    }
    if (!hasHex(obj.audit_hash, 32)) {
      errors.push("audit_hash must be lowercase hex");
    }
    if (typeof obj.hash_algo !== "string" || obj.hash_algo.trim() === "") {
      errors.push("hash_algo must be a non-empty string");
    }

    const hints = traceDecisionHints(obj.trace);
    if (hints.hasBlocked && obj.final_decision !== "Blocked") {
      errors.push("final_decision inconsistent with trace (blocked hint)");
    } else if (!hints.hasBlocked && hints.hasFlagged && obj.final_decision !== "Flagged") {
      errors.push("final_decision inconsistent with trace (flagged hint)");
    } else if (!hints.hasBlocked && !hints.hasFlagged && obj.final_decision !== "Approved") {
      warnings.push("final_decision may be inconsistent with trace; use Zig verifier for authority");
    }

    if (!hasHex(obj.record_hash || "", 64)) {
      warnings.push("record_hash missing or not 64-char lowercase hex");
    }
    if (obj.prev_record_hash && !hasHex(obj.prev_record_hash, 64)) {
      warnings.push("prev_record_hash present but not 64-char lowercase hex");
    }

    return { errors, warnings };
  }

  function handleVerify() {
    const file = nodes.artifactFile.files && nodes.artifactFile.files[0];
    if (!file) {
      setText(nodes.verifyOutput, "Select a .json or .jsonl artifact first.");
      nodes.verifyOutput.className = "output warn";
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = parseArtifactInput(String(reader.result || ""));
        state.loadedArtifact = parsed;
        const result = sanityCheckArtifact(parsed);
        const report = {
          mode: "phase_a_sanity_check",
          note: "This does not replace the Zig verifier.",
          errors: result.errors,
          warnings: result.warnings,
        };
        setText(nodes.verifyOutput, JSON.stringify(report, null, 2));
        nodes.verifyOutput.className =
          "output " + (result.errors.length === 0 ? "ok" : "error");
        renderAuditView(extractAuditView(parsed));
      } catch (err) {
        setText(nodes.verifyOutput, `Invalid artifact: ${String(err)}`);
        nodes.verifyOutput.className = "output error";
      }
    };
    reader.onerror = () => {
      setText(nodes.verifyOutput, "Failed to read selected file.");
      nodes.verifyOutput.className = "output error";
    };
    reader.readAsText(file);
  }

  function exportEvidencePack() {
    const payload = {
      exported_at_utc: new Date().toISOString(),
      generated_response: state.generatedResponse,
      loaded_artifact: state.loadedArtifact,
      audit_view: state.auditView,
      non_claim: "Phase A UI export; cryptographic authority remains Rust + Zig verifier flow.",
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nexo-evidence-pack-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setText(nodes.auditOutput, "Evidence pack exported.");
    nodes.auditOutput.className = "output ok";
  }

  setDefaults();
  if (nodes.generateForm) {
    nodes.generateForm.addEventListener("submit", handleGenerate);
  }
  if (nodes.verifyBtn) {
    nodes.verifyBtn.addEventListener("click", handleVerify);
  }
  if (nodes.exportBtn) {
    nodes.exportBtn.addEventListener("click", exportEvidencePack);
  }
})();
