(function() {
  const stateNodes = {
    system_status: document.getElementById('meta-system_status'),
    peers_count: document.getElementById('meta-peers_count'),
    network_mode: document.getElementById('meta-network_mode'),
    mesh_status: document.getElementById('meta-mesh_status'),
    relay_status: document.getElementById('meta-relay_status'),
    ai_last_insight: document.getElementById('meta-ai_last_insight'),
    recent_event_hash: document.getElementById('meta-recent_event_hash'),
    last_sync: document.getElementById('meta-last_sync'),
    last_event_hash: document.getElementById('meta-last_event_hash'),
    event_type: document.getElementById('meta-event_type'),
    event_timestamp: document.getElementById('meta-event_timestamp'),
    event_origin: document.getElementById('meta-event_origin'),
    event_channel: document.getElementById('meta-event_channel'),
  };

  const cardNodes = {
    system_status: document.getElementById('value-system_status'),
    peers_count: document.getElementById('value-peers_count'),
    network_mode: document.getElementById('value-network_mode'),
    mesh_status: document.getElementById('value-mesh_status'),
    relay_status: document.getElementById('value-relay_status'),
    ai_last_insight: document.getElementById('value-ai_last_insight'),
    recent_event_hash: document.getElementById('value-recent_event_hash'),
    health: document.getElementById('value-health'),
    events: document.getElementById('value-events'),
    healthCard: document.getElementById('card-integrity'),
    ai_recent_insights: document.getElementById('value-ai_recent_insights'),
  };
  const meshPreviewNode = document.getElementById('mesh-preview');
  const eventsCardNode = document.getElementById('card-events');
  const aiCardNode = document.getElementById('card-ai');
  const networkCardNode = document.getElementById('card-network');
  const relayCardNode = document.getElementById('card-relay');
  const topologyHintNode = document.getElementById('topology-hint');
  const causes = {
    events: document.getElementById('cause-events'),
    ai: document.getElementById('cause-ai'),
    network: document.getElementById('cause-network'),
    relay: document.getElementById('cause-relay'),
  };
  let previousEventHash = null;
  let eventPulseTimer = null;
  let previousAiInsight = null;
  let aiPulseTimer = null;
  let previousPeersCount = null;
  let previousRelayStatus = null;
  let networkPulseTimer = null;
  let relayPulseTimer = null;

  const recentEventsMax = 5;
  const recentAiInsightsMax = 3;

  const metaLabel = {
    system_status: 'system_status',
    peers_count: 'peers_count',
    network_mode: 'network_mode',
    mesh_status: 'mesh_status',
    relay_status: 'relay_status',
    ai_last_insight: 'ai_last_insight',
    recent_event_hash: 'recent_event_hash',
    last_event_hash: 'last_event_hash',
    event_type: 'event_type',
    event_timestamp: 'event_timestamp',
    event_origin: 'event_origin',
    event_channel: 'event_channel',
    last_sync: 'last_sync',
  };

  const labelByKey = {
    system_status: 'system_status',
    peers_count: 'Peers',
    relay_status: 'Relay',
    ai_last_insight: 'AI',
    recent_event_hash: 'Hash Pulse',
    events: 'Events',
  };

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function normalizePeersCount(value) {
    const n = Number.parseInt(value, 10);
    if (!Number.isFinite(n) || n <= 0) {
      return 0;
    }
    return n;
  }

  function renderMeshPreview(peersCountRaw) {
    if (!meshPreviewNode) {
      return;
    }

    const peerCount = normalizePeersCount(peersCountRaw);
    const renderedPeers = Math.min(peerCount, 10);

    const localNode = '<span class="mesh-dot mesh-dot-local" title="local node" aria-label="local node"></span>';
    const peerNodes = Array.from({ length: renderedPeers }, (_item, index) => {
      const delay = (index % 4) * 120;
      return `<span class="mesh-dot mesh-dot-peer" title="peer ${index + 1}" aria-label="peer ${index + 1}" style="animation-delay:${delay}ms"></span>`;
    }).join('');

    meshPreviewNode.innerHTML = `${localNode}${peerNodes}`;

    const summary = renderedPeers === 0
      ? 'peers: 0 (local only)'
      : `peers: ${peerCount} (${renderedPeers} shown)`;
    meshPreviewNode.setAttribute('data-peers', String(peerCount));
    meshPreviewNode.setAttribute('aria-label', `network mesh preview (${summary})`);
  }

  function updateTopologyHint(peersCountRaw) {
    if (!topologyHintNode) {
      return;
    }

    const peersCount = normalizePeersCount(peersCountRaw);
    if (peersCount > 10) {
      topologyHintNode.textContent = 'topology: local + peers (>10)';
      return;
    }

    topologyHintNode.textContent = 'topology: local + peers';
  }

  function sanitizeEvents(state) {
    const events = Array.isArray(state.recent_events) ? state.recent_events.slice(0, recentEventsMax) : [];
    if (events.length > 0) {
      return events;
    }

    return [{
      hash: state.last_event_hash || 'n/a',
      type: state.event_type || 'n/a',
      origin: state.event_origin || 'n/a',
      channel: state.event_channel || 'n/a',
      timestamp: state.event_timestamp || 'n/a',
    }];
  }

  function formatEvents(state, shouldPulseLatestRow = false) {
    const events = sanitizeEvents(state);
    return events.map((event, index) => {
      let rowClass = index === 0 ? 'event-row latest' : 'event-row';
      if (index === 0 && shouldPulseLatestRow) {
        rowClass += ' pulse';
      }
      return `<div class="${rowClass}">
        #${index + 1} ${escapeHtml(event.timestamp || 'n/a')} | ${escapeHtml(event.origin || 'n/a')} | ${escapeHtml(event.channel || 'n/a')}
        type=${escapeHtml(event.type || 'n/a')}
        hash=${escapeHtml(event.hash || 'n/a')}
      </div>`;
    }).join('');
  }

  function sanitizeAiInsights(state) {
    const insights = Array.isArray(state.recent_ai_insights) ? state.recent_ai_insights.slice(0, recentAiInsightsMax) : [];
    if (insights.length > 0) {
      return insights;
    }

    return [{
      text: state.ai_last_insight || 'No insight available.',
      timestamp: state.last_sync || 'n/a',
      type: 'unknown',
      origin: 'unknown',
    }];
  }

  function formatAiInsights(state, shouldPulseLatestRow = false) {
    const insights = sanitizeAiInsights(state);
    return insights.map((insight, index) => {
      let rowClass = index === 0 ? 'ai-insight-row latest' : 'ai-insight-row';
      if (index === 0 && shouldPulseLatestRow) {
        rowClass += ' pulse';
      }

      return `<div class="${rowClass}">
        #${index + 1} ${escapeHtml(insight.timestamp || 'n/a')} | ${escapeHtml(insight.type || 'n/a')} | ${escapeHtml(insight.origin || 'unknown')}
        <div>${escapeHtml(insight.text || '')}</div>
      </div>`;
    }).join('');
  }

  function setCardCause(cardName, text) {
    const causeNode = causes[cardName];
    if (!causeNode) {
      return;
    }
    causeNode.textContent = text;
  }

  function triggerEventPulse() {
    if (!eventsCardNode) {
      return;
    }

    eventsCardNode.classList.remove('card-events-pulse');
    void eventsCardNode.offsetWidth;
    eventsCardNode.classList.add('card-events-pulse');

    clearTimeout(eventPulseTimer);
    eventPulseTimer = setTimeout(() => {
      if (eventsCardNode) {
        eventsCardNode.classList.remove('card-events-pulse');
      }
    }, 600);
  }

  function normalizeInsight(value) {
    if (value === null || value === undefined) {
      return null;
    }
    const text = String(value).trim();
    if (text === '' || text.toLowerCase() === 'n/a') {
      return null;
    }
    return text;
  }

  function triggerAiPulse() {
    if (!aiCardNode) {
      return;
    }

    aiCardNode.classList.remove('card-ai-pulse');
    void aiCardNode.offsetWidth;
    aiCardNode.classList.add('card-ai-pulse');

    clearTimeout(aiPulseTimer);
    aiPulseTimer = setTimeout(() => {
      if (aiCardNode) {
        aiCardNode.classList.remove('card-ai-pulse');
      }
    }, 550);
  }

  function triggerNetworkPulse() {
    if (!networkCardNode) {
      return;
    }

    networkCardNode.classList.remove('card-network-pulse');
    void networkCardNode.offsetWidth;
    networkCardNode.classList.add('card-network-pulse');

    clearTimeout(networkPulseTimer);
    networkPulseTimer = setTimeout(() => {
      if (networkCardNode) {
        networkCardNode.classList.remove('card-network-pulse');
      }
    }, 620);
  }

  function triggerRelayPulse() {
    if (!relayCardNode) {
      return;
    }

    relayCardNode.classList.remove('card-relay-pulse');
    void relayCardNode.offsetWidth;
    relayCardNode.classList.add('card-relay-pulse');

    clearTimeout(relayPulseTimer);
    relayPulseTimer = setTimeout(() => {
      if (relayCardNode) {
        relayCardNode.classList.remove('card-relay-pulse');
      }
    }, 620);
  }

  function shouldPulseForNetwork(state) {
    const peersCount = state && state.peers_count !== undefined ? String(state.peers_count).trim() : null;

    if (peersCount === null || peersCount === '') {
      if (previousPeersCount === null) {
        previousPeersCount = peersCount;
      }
      return false;
    }

    if (previousPeersCount === null) {
      previousPeersCount = peersCount;
      return false;
    }

    if (peersCount !== previousPeersCount) {
      previousPeersCount = peersCount;
      return true;
    }

    return false;
  }

  function shouldPulseForRelay(state) {
    const relayStatus = state && state.relay_status !== undefined ? String(state.relay_status).trim() : null;

    if (relayStatus === null || relayStatus === '') {
      if (previousRelayStatus === null) {
        previousRelayStatus = relayStatus;
      }
      return false;
    }

    if (previousRelayStatus === null) {
      previousRelayStatus = relayStatus;
      return false;
    }

    if (relayStatus !== previousRelayStatus) {
      previousRelayStatus = relayStatus;
      return true;
    }

    return false;
  }

  function shouldPulseForAiInsight(state) {
    const insight = normalizeInsight(state && state.ai_last_insight);

    if (insight === null) {
      if (previousAiInsight === null) {
        previousAiInsight = null;
      }
      return false;
    }

    if (previousAiInsight === null) {
      previousAiInsight = insight;
      return false;
    }

    if (insight !== previousAiInsight) {
      previousAiInsight = insight;
      return true;
    }

    return false;
  }

  function shouldPulseForEvents(state) {
    const events = sanitizeEvents(state);
    const latest = events[0];
    const latestHash = latest && latest.hash ? `${latest.hash}` : null;

    if (latestHash === null || latestHash === 'n/a') {
      if (previousEventHash === null) {
        previousEventHash = latestHash;
      }
      return false;
    }

    if (previousEventHash === null) {
      previousEventHash = latestHash;
      return false;
    }

    if (latestHash !== previousEventHash) {
      previousEventHash = latestHash;
      return true;
    }

    return false;
  }

  const sourceNode = document.getElementById('data-source');
  const healthCardNode = cardNodes.healthCard;
  const healthBannerNode = document.getElementById('health-banner');
  const healthPolicyNode = document.getElementById('health-policy-state');
  const healthSourceNode = document.getElementById('health-policy-source');
  const healthDotNode = document.getElementById('health-dot');
  const seedTargets = [];
  const cardNames = ['core', 'network', 'relay', 'ai', 'hash', 'events', 'integrity'];
  for (let i = 0; i < cardNames.length; i++) {
    const cardName = cardNames[i];
    const element = document.getElementById(`card-${cardName}`);
    if (element) {
      seedTargets.push(element);
    }
  }

  function updateMetaText(key, value) {
    if (!stateNodes[key]) {
      return;
    }
    stateNodes[key].textContent = `${metaLabel[key]}: ${value}`;
  }

  function updateCardText(key, value) {
    if (!cardNodes[key]) {
      return;
    }

    if (key === 'peers_count') {
      cardNodes[key].textContent = `${labelByKey[key]}: ${value}`;
      return;
    }

    if (key === 'network_mode') {
      if (!cardNodes.network_mode) return;
      cardNodes.network_mode.textContent = `network_mode: ${value}`;
      return;
    }

    if (key === 'mesh_status') {
      if (!cardNodes.mesh_status) return;
      cardNodes.mesh_status.textContent = `mesh_status: ${value}`;
      return;
    }

    if (key === 'ai_last_insight') {
      cardNodes[key].textContent = `${labelByKey[key]}: ${value}`;
      return;
    }

    if (key === 'recent_event_hash') {
      cardNodes[key].textContent = `${labelByKey[key]}: ${value}`;
      return;
    }

    if (key === 'events') {
      return;
    }

    if (key === 'recent_ai_insights') {
      return;
    }

    if (key === 'last_event_hash' || key === 'event_type' || key === 'event_timestamp' || key === 'event_origin' || key === 'event_channel') {
      return;
    }

    cardNodes[key].textContent = value;
  }

  function applyState(data) {
    const state = data.state;

    for (const key of Object.keys(state)) {
      updateMetaText(key, state[key]);
      updateCardText(key, state[key]);
    }

    if (state && state.peers_count !== undefined) {
      renderMeshPreview(state.peers_count);
      updateTopologyHint(state.peers_count);
    } else {
      updateTopologyHint(0);
    }

    if (cardNodes.events) {
      const hasEventPulse = shouldPulseForEvents(state);
      if (hasEventPulse) {
        triggerEventPulse();
        setCardCause('events', 'latest event changed');
      }
      cardNodes.events.innerHTML = formatEvents(state, hasEventPulse);
    }

    const hasAiPulse = shouldPulseForAiInsight(state);
    if (hasAiPulse) {
      triggerAiPulse();
      setCardCause('ai', 'new insight detected');
    }

    if (cardNodes.ai_recent_insights) {
      cardNodes.ai_recent_insights.innerHTML = formatAiInsights(state, hasAiPulse);
    }

    const hasNetworkPulse = shouldPulseForNetwork(state);
    if (hasNetworkPulse) {
      triggerNetworkPulse();
      setCardCause('network', 'peer count changed');
    }

    const hasRelayPulse = shouldPulseForRelay(state);
    if (hasRelayPulse) {
      triggerRelayPulse();
      setCardCause('relay', 'relay status changed');
    }

    if (state.last_sync && stateNodes.last_sync) {
      stateNodes.last_sync.textContent = `last_sync: ${state.last_sync}`;
    }

    if (Array.isArray(data.seed)) {
      data.seed.forEach((s, i) => {
        if (!seedTargets[i]) return;
        seedTargets[i].style.setProperty('--dx', s.drift_x);
        seedTargets[i].style.setProperty('--dy', s.drift_y);
        seedTargets[i].style.setProperty('--alpha', s.opacity);
        seedTargets[i].style.setProperty('--flicker', s.flicker);
      });
    }

    if (sourceNode && data.data_source) {
      sourceNode.textContent = `source: ${data.data_source}`;
    }

    if (data.last_updated) {
      const out = document.getElementById('last-updated');
      out.textContent = data.last_updated;
    }
  }

  function normalizeHealthState(state) {
    if (state === 'healthy' || state === 'degraded' || state === 'demo' || state === 'unavailable') {
      return state;
    }

    return 'unavailable';
  }

  function applyHealth(data) {
    if (!cardNodes.health) {
      return;
    }

    const uiStatus = normalizeHealthState(data && data.ui_status ? data.ui_status : 'unavailable');
    const dataSource = data && data.data_source ? data.data_source : 'unknown';
    const sourceType = data && data.source_type ? data.source_type : 'unknown';
    const adapterStatus = data && data.adapter_status ? data.adapter_status : 'unreachable';
    const lastUpdated = data && data.last_updated ? data.last_updated : 'n/a';
    const integrityMessage = data && data.integrity_message ? data.integrity_message : 'health source unreachable';

    cardNodes.health.innerHTML = `
      source: ${dataSource}<br />
      adapter_status: ${adapterStatus}<br />
      source_type: ${sourceType}<br />
      ui_status: ${uiStatus}<br />
      integrity_message: ${integrityMessage}<br />
      last_updated: ${lastUpdated}
    `;

    if (healthBannerNode) {
      healthBannerNode.classList.remove('health-state-healthy', 'health-state-degraded', 'health-state-demo', 'health-state-unavailable');
      healthBannerNode.classList.add(`health-state-${uiStatus}`);

      if (healthPolicyNode) {
        healthPolicyNode.textContent = uiStatus;
      }

      if (healthSourceNode) {
        healthSourceNode.textContent = `Source: ${sourceType}`;
      }
    }

    if (healthDotNode) {
      healthDotNode.style.opacity = '1';
      healthDotNode.classList.remove('health-state-healthy', 'health-state-degraded', 'health-state-demo', 'health-state-unavailable');
      healthDotNode.classList.add(`health-state-${uiStatus}`);
    }

    if (healthCardNode) {
      healthCardNode.classList.remove('card-health-warning', 'card-health-degraded', 'card-health-unavailable');
      if (uiStatus === 'degraded' || uiStatus === 'demo') {
        healthCardNode.classList.add('card-health-warning', 'card-health-degraded');
      }

      if (uiStatus === 'unavailable') {
        healthCardNode.classList.add('card-health-unavailable');
      }
    }
  }

  async function fetchStatus() {
    try {
      const response = await fetch('/api/status');
      if (!response.ok) return;
      const payload = await response.json();
      applyState(payload);
    } catch (_err) {
      // fail-closed on UI side: preserve old state silently
    }
  }

  async function fetchHealth() {
    try {
      const response = await fetch('/api/health');
      if (!response.ok) {
        throw new Error('health endpoint not ok');
      }
      const payload = await response.json();
      applyHealth(payload);
    } catch (_err) {
      applyHealth({
        ui_status: 'unavailable',
        data_source: 'unknown',
        source_type: 'unreachable',
        adapter_status: 'request_failed',
        last_updated: new Date().toISOString().replace('T', ' ').replace('Z', ' UTC'),
        seed: [],
      });
    }
  }

  async function simulate(action) {
    try {
      const response = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      });

      if (!response.ok) return;
      const payload = await response.json();
      applyState(payload);
      await fetchHealth();
    } catch (_err) {
      // fail-closed on UI side: preserve old state silently
    }
  }

  document.getElementById('refresh-btn').addEventListener('click', () => {
    fetchStatus();
    fetchHealth();
  });
  document.querySelectorAll('.simulate-button').forEach((button) => {
    button.addEventListener('click', () => simulate(button.getAttribute('data-action')));
  });
  setInterval(() => {
    fetchStatus();
    fetchHealth();
  }, 3000);

  fetchStatus();
  fetchHealth();
})();
