(function() {
  const POLL_MS = 3000;

  const nodes = {
    refreshBtn: document.getElementById('refresh-btn'),
    sourceMode: document.getElementById('source-mode'),
    sourceTypeTop: document.getElementById('source-type'),
    lastUpdated: document.getElementById('last-updated'),
    systemStatus: document.getElementById('core-system-status'),
    finalDecision: document.getElementById('core-final-decision'),
    traceKind: document.getElementById('trace-kind'),
    traceSummary: document.getElementById('trace-summary'),
    traceOrigin: document.getElementById('trace-origin'),
    traceTimestamp: document.getElementById('trace-timestamp'),
    auditLastEventHash: document.getElementById('audit-last-event-hash'),
    auditRecentEventHash: document.getElementById('audit-recent-event-hash'),
    auditEventType: document.getElementById('audit-event-type'),
    auditEventOrigin: document.getElementById('audit-event-origin'),
    auditEventChannel: document.getElementById('audit-event-channel'),
    auditEventTimestamp: document.getElementById('audit-event-timestamp'),
    ctxLatestChangeSource: document.getElementById('ctx-latest-change-source'),
    ctxWriteStatus: document.getElementById('ctx-write-status'),
    ctxRelayStatus: document.getElementById('ctx-relay-status'),
    ctxJuliaSummary: document.getElementById('ctx-julia-summary'),
    ctxJuliaFlow: document.getElementById('ctx-julia-flow'),
    ctxJuliaRegime: document.getElementById('ctx-julia-regime'),
    ctxEventCount: document.getElementById('ctx-event-count'),
    ctxLastSync: document.getElementById('ctx-last-sync'),
    ctxDataSource: document.getElementById('ctx-data-source'),
    ctxSourceType: document.getElementById('ctx-source-type'),
    ctxAdapterStatus: document.getElementById('ctx-adapter-status'),
    ctxPeersCount: document.getElementById('ctx-peers-count'),
    ctxMeshStatus: document.getElementById('ctx-mesh-status'),
  };

  function decisionFromEventType(eventType) {
    switch (String(eventType || '')) {
      case 'system_event:approved':
        return { text: 'Approved', tone: 'decision-approved' };
      case 'system_event:flagged':
        return { text: 'Flagged For Review', tone: 'decision-flagged' };
      case 'system_event:blocked':
        return { text: 'Blocked', tone: 'decision-blocked' };
      default:
        return { text: 'No Decision Observed', tone: 'decision-neutral' };
    }
  }

  function modeLabel(sourceType, adapterStatus) {
    if (sourceType === 'demo' || adapterStatus === 'manual_demo_override') {
      return 'demo mode';
    }
    if (sourceType === 'core') {
      return 'connected to core';
    }
    if (sourceType === 'sqlite' || sourceType === 'file') {
      return 'offline local state';
    }
    if (sourceType === 'fallback') {
      return 'offline mode';
    }
    return 'state unavailable';
  }

  function safeValue(value, fallback = 'n/a') {
    if (value === null || value === undefined) {
      return fallback;
    }
    const text = String(value).trim();
    return text === '' ? fallback : text;
  }

  function updateText(node, value) {
    if (!node) {
      return;
    }
    node.textContent = value;
  }

  function applyDecision(eventType) {
    const decision = decisionFromEventType(eventType);
    if (!nodes.finalDecision) {
      return;
    }

    nodes.finalDecision.classList.remove(
      'decision-approved',
      'decision-flagged',
      'decision-blocked',
      'decision-neutral',
    );
    nodes.finalDecision.classList.add(decision.tone);
    nodes.finalDecision.textContent = decision.text;
  }

  function applyState(payload) {
    const state = payload.state || {};
    const sourceType = safeValue(payload.source_type, 'unknown');
    const adapterStatus = safeValue(payload.adapter_status, 'unavailable');
    const mode = modeLabel(sourceType, adapterStatus);

    updateText(nodes.sourceMode, `mode: ${mode}`);
    updateText(nodes.sourceTypeTop, sourceType);
    updateText(nodes.lastUpdated, safeValue(payload.last_updated));

    updateText(nodes.systemStatus, safeValue(state.system_status, 'unknown'));
    applyDecision(state.event_type);

    updateText(nodes.traceKind, safeValue(state.latest_change_kind));
    updateText(nodes.traceSummary, safeValue(state.latest_change_summary));
    updateText(nodes.traceOrigin, safeValue(state.latest_change_origin));
    updateText(nodes.traceTimestamp, safeValue(state.latest_change_timestamp));

    updateText(nodes.auditLastEventHash, safeValue(state.last_event_hash));
    updateText(nodes.auditRecentEventHash, safeValue(state.recent_event_hash));
    updateText(nodes.auditEventType, safeValue(state.event_type));
    updateText(nodes.auditEventOrigin, safeValue(state.event_origin));
    updateText(nodes.auditEventChannel, safeValue(state.event_channel));
    updateText(nodes.auditEventTimestamp, safeValue(state.event_timestamp));

    updateText(nodes.ctxLatestChangeSource, safeValue(state.latest_change_source));
    updateText(nodes.ctxWriteStatus, safeValue(state.write_status));
    updateText(nodes.ctxRelayStatus, safeValue(state.relay_status));
    updateText(nodes.ctxJuliaSummary, safeValue(state.julia_observation_summary, 'not available'));
    updateText(nodes.ctxJuliaFlow, safeValue(state.julia_observation_flow_intensity));
    updateText(nodes.ctxJuliaRegime, safeValue(state.julia_observation_regime_hint));
    updateText(nodes.ctxEventCount, String(Array.isArray(state.recent_events) ? state.recent_events.length : 0));
    updateText(nodes.ctxLastSync, safeValue(state.last_sync));
    updateText(nodes.ctxDataSource, safeValue(payload.data_source));
    updateText(nodes.ctxSourceType, sourceType);
    updateText(nodes.ctxAdapterStatus, adapterStatus);
    updateText(nodes.ctxPeersCount, safeValue(state.peers_count, '0'));
    updateText(nodes.ctxMeshStatus, safeValue(state.mesh_status));
  }

  function applyUnavailableState() {
    updateText(nodes.sourceMode, 'mode: state unavailable');
    updateText(nodes.sourceTypeTop, 'unavailable');
    updateText(nodes.lastUpdated, new Date().toISOString().replace('T', ' ').replace('Z', ' UTC'));
  }

  async function fetchStatus() {
    try {
      const response = await fetch('/api/status');
      if (!response.ok) {
        applyUnavailableState();
        return;
      }
      const payload = await response.json();
      applyState(payload);
    } catch (_error) {
      applyUnavailableState();
    }
  }

  if (nodes.refreshBtn) {
    nodes.refreshBtn.addEventListener('click', fetchStatus);
  }

  setInterval(fetchStatus, POLL_MS);
  fetchStatus();
})();
