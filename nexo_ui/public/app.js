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
    recent_chat_messages: document.getElementById('value-recent_chat_messages'),
    recent_flow: document.getElementById('value-recent_flow'),
    healthCard: document.getElementById('card-integrity'),
    ai_recent_insights: document.getElementById('value-ai_recent_insights'),
  };
  const meshPreviewNode = document.getElementById('mesh-preview');
  const eventsCardNode = document.getElementById('card-events');
  const aiCardNode = document.getElementById('card-ai');
  const networkCardNode = document.getElementById('card-network');
  const relayCardNode = document.getElementById('card-relay');
  const topologyHintNode = document.getElementById('topology-hint');
  const networkCauseHintNode = document.getElementById('network-cause-hint');
  const chatInputNode = document.getElementById('chat-message-input');
  const chatSendBtnNode = document.getElementById('send-chat-message');
  const chatSendModeNode = document.getElementById('chat-send-mode');
  const chatByteCounterNode = document.getElementById('chat-byte-counter');
  const chatSendStatusNode = document.getElementById('chat-send-status');
  const chatCardNode = document.getElementById('card-globalchat');
  const liveFlowCardNode = document.getElementById('card-liveflow');
  const chatSourceNode = document.getElementById('chat-source-indicator');
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
  let meshPulseTimer = null;
  let hasInitializedNetworkState = false;
  let previousChatHash = null;
  let chatPulseTimer = null;
  let meshChatPulseTimer = null;
  let previousLiveFlowTop = null;
  let liveFlowPulseTimer = null;

  const recentEventsMax = 5;
  const recentAiInsightsMax = 3;
  const recentChatMessagesMax = 5;
  const recentFlowMax = 5;

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

  function renderMeshPreview(peersCountRaw, highlight = null) {
    if (!meshPreviewNode) {
      return;
    }

    const peerCount = normalizePeersCount(peersCountRaw);
    const renderedPeers = Math.min(peerCount, 10);

    const localClasses = ['mesh-dot', 'mesh-dot-local'];
    if (highlight && highlight.type === 'local') {
      localClasses.push('mesh-dot-local-highlight');
    }
    const localNode = `<span class="${localClasses.join(' ')}" title="local node" aria-label="local node" data-peer="local"></span>`;
    const peerNodes = Array.from({ length: renderedPeers }, (_item, index) => {
      const delay = (index % 4) * 120;
      const classes = ['mesh-dot', 'mesh-dot-peer'];
      if (highlight && highlight.type === 'peer' && highlight.index === index + 1) {
        classes.push('mesh-dot-peer-highlight');
      }
      return `<span class="${classes.join(' ')}" title="peer ${index + 1}" aria-label="peer ${index + 1}" style="animation-delay:${delay}ms" data-peer="${index + 1}"></span>`;
    }).join('');

    meshPreviewNode.innerHTML = `${localNode}${peerNodes}`;

    const summary = renderedPeers === 0
      ? 'peers: 0 (local only)'
      : `peers: ${peerCount} (${renderedPeers} shown)`;
    meshPreviewNode.setAttribute('data-peers', String(peerCount));
    meshPreviewNode.setAttribute('aria-label', `network mesh preview (${summary})`);

    if (highlight && highlight.type) {
      triggerMeshDotHighlight(highlight);
    }
  }

  function parseStableMeshOrigin(origin) {
    if (origin === null || origin === undefined) {
      return null;
    }

    const raw = String(origin).trim().toLowerCase();
    if (!raw) {
      return null;
    }

    if (raw === 'local' || raw === 'self' || raw === 'localhost' || raw === 'me') {
      return { kind: 'local' };
    }

    const match = raw.match(/^(?:node|peer|user)[-_]?(?:id[_-]?)?(.+)$/);
    if (!match) {
      return null;
    }

    const value = match[1].trim();
    if (!value) {
      return null;
    }

    return { kind: 'named', value };
  }

  function stableStringHash(input) {
    let h = 0;
    for (let i = 0; i < input.length; i++) {
      h = (h * 31 + input.charCodeAt(i)) >>> 0;
    }
    return h;
  }

  function resolveChatOriginForPeerDot(origin, peersCountRaw) {
    const parsed = parseStableMeshOrigin(origin);
    if (!parsed) {
      return null;
    }

    const peerCount = normalizePeersCount(peersCountRaw);
    if (peerCount <= 0) {
      if (parsed.kind === 'local') {
        return { type: 'local' };
      }
      return null;
    }

    if (parsed.kind === 'local') {
      return { type: 'local' };
    }

    const numberMatch = parsed.value.match(/(\d+)/);
    if (numberMatch) {
      const asNumber = Number.parseInt(numberMatch[0], 10);
      if (Number.isFinite(asNumber) && asNumber >= 0) {
        const idx = (asNumber % peerCount) + 1;
        return { type: 'peer', index: idx };
      }
    }

    const idx = (stableStringHash(parsed.value) % peerCount) + 1;
    return { type: 'peer', index: idx };
  }

  function triggerMeshDotHighlight(target) {
    if (!meshPreviewNode || !target || !target.type) {
      return;
    }

    clearTimeout(meshChatPulseTimer);
    const dots = meshPreviewNode.querySelectorAll('.mesh-dot');
    dots.forEach((dot) => {
      dot.classList.remove('mesh-dot-peer-highlight', 'mesh-dot-local-highlight');
    });

    let selector = '';
    if (target.type === 'local') {
      selector = '.mesh-dot-local';
    } else if (target.type === 'peer' && target.index > 0) {
      selector = `.mesh-dot-peer[data-peer="${target.index}"]`;
    }

    const dot = selector ? meshPreviewNode.querySelector(selector) : null;
    if (!dot) {
      return;
    }

    if (target.type === 'local') {
      dot.classList.add('mesh-dot-local-highlight');
    } else {
      dot.classList.add('mesh-dot-peer-highlight');
    }

    meshPreviewNode.classList.add('mesh-preview-highlight');
    meshChatPulseTimer = setTimeout(() => {
      dot.classList.remove('mesh-dot-peer-highlight', 'mesh-dot-local-highlight');
      meshPreviewNode.classList.remove('mesh-preview-highlight');
    }, 700);
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

  function sanitizeChatMessages(state) {
    const messages = Array.isArray(state.recent_chat_messages) ? state.recent_chat_messages.slice(0, recentChatMessagesMax) : [];
    return messages;
  }

  function describeSurfaceMode(sourceType, adapterStatus = '') {
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

  function describeChatSource(sourceType) {
    if (sourceType === 'core') {
      return 'connected to core';
    }
    if (sourceType === 'sqlite' || sourceType === 'file') {
      return 'offline local state';
    }
    if (sourceType === 'fallback' || sourceType === 'demo') {
      return 'demo or fallback';
    }
    return 'state unavailable';
  }

  function describeChatEmptyState(data) {
    const sourceType = String(data && data.source_type ? data.source_type : 'unknown');
    if (sourceType === 'core') {
      return 'No chat messages from the core yet.';
    }
    if (sourceType === 'sqlite' || sourceType === 'file') {
      return 'Offline local state is read-only.';
    }
    return 'No chat messages available in this mode.';
  }

  function describeFlowEmptyState(data) {
    const sourceType = String(data && data.source_type ? data.source_type : 'unknown');
    if (sourceType === 'core') {
      return 'No live flow from the core yet.';
    }
    return 'No live flow available in this mode.';
  }

  function formatChatMessages(state, data) {
    const messages = sanitizeChatMessages(state);
    if (messages.length === 0) {
      return `<span class="empty-state">${escapeHtml(describeChatEmptyState(data))}</span>`;
    }

    return messages.map((message, index) => {
      const rowClass = index === 0 ? 'chat-row latest' : 'chat-row';
      const origin = escapeHtml(message.origin || 'unknown');
      const channel = escapeHtml(message.channel || 'global');
      const timestamp = escapeHtml(message.timestamp || 'n/a');
      return `<div class="${rowClass}">
        <span class="chat-meta">#${index + 1} | origin=${origin} | channel=${channel}<br />${timestamp}</span>
        <span class="chat-text">${escapeHtml(message.text || '')}</span><br />
        <span class="mono chat-hash">hash=${escapeHtml(message.hash || 'n/a')}</span>
      </div>`;
    }).join('');
  }

  function sanitizeLiveFlow(state) {
    const items = Array.isArray(state.recent_flow) ? state.recent_flow.slice(0, recentFlowMax) : [];
    if (items.length > 0) {
      return items;
    }

    return [];
  }

  function sanitizeFlowKind(value) {
    const kind = String(value || 'event');
    if (kind === 'ai' || kind === 'chat' || kind === 'event') {
      return kind;
    }

    return 'event';
  }

  function formatLiveFlow(state, data, shouldPulseLatestRow = false) {
    const flowItems = sanitizeLiveFlow(state);
    if (flowItems.length === 0) {
      return `<span class="empty-state">${escapeHtml(describeFlowEmptyState(data))}</span>`;
    }

    return flowItems.map((item, index) => {
      const kind = sanitizeFlowKind(item.kind);
      const summary = escapeHtml(item.summary || '');
      const hash = item.hash || '';
      let rowClass = `flow-item flow-item-${kind} ${index === 0 ? 'latest' : ''}`;
      if (index === 0 && shouldPulseLatestRow) {
        rowClass += ' pulse';
      }
      return `<div class="${rowClass}">
        #${index + 1} ${escapeHtml(item.timestamp || 'n/a')} | ${escapeHtml(item.origin || 'unknown')}
        (${escapeHtml(kind)})${item.channel ? ` | ${escapeHtml(item.channel)}` : ''}
        <div class="flow-summary">${summary}</div>
        ${hash ? `<span class="mono flow-hash">hash=${escapeHtml(hash)}</span>` : ''}
      </div>`;
    }).join('');
  }

  function flowTopSignature(state) {
    const flowItems = sanitizeLiveFlow(state);
    const top = flowItems[0];
    if (!top) {
      return null;
    }
    return [
      sanitizeFlowKind(top.kind),
      top.origin || 'unknown',
      top.summary || '',
      top.timestamp || 'n/a',
      top.hash || '',
      top.channel || '',
    ].join('|');
  }

  function shouldPulseForLiveFlow(state) {
    const signature = flowTopSignature(state);

    if (signature === null) {
      if (previousLiveFlowTop === null) {
        previousLiveFlowTop = null;
      }
      return false;
    }

    if (previousLiveFlowTop === null) {
      previousLiveFlowTop = signature;
      return false;
    }

    if (signature !== previousLiveFlowTop) {
      previousLiveFlowTop = signature;
      return true;
    }

    return false;
  }

  function triggerLiveFlowPulse() {
    if (!liveFlowCardNode) {
      return;
    }

    liveFlowCardNode.classList.remove('card-liveflow-pulse');
    void liveFlowCardNode.offsetWidth;
    liveFlowCardNode.classList.add('card-liveflow-pulse');

    clearTimeout(liveFlowPulseTimer);
    liveFlowPulseTimer = setTimeout(() => {
      if (liveFlowCardNode) {
        liveFlowCardNode.classList.remove('card-liveflow-pulse');
      }
    }, 620);
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

  function triggerMeshPulse() {
    if (!meshPreviewNode) {
      return;
    }

    meshPreviewNode.classList.remove('mesh-preview-pulse');
    void meshPreviewNode.offsetWidth;
    meshPreviewNode.classList.add('mesh-preview-pulse');

    clearTimeout(meshPulseTimer);
    meshPulseTimer = setTimeout(() => {
      if (meshPreviewNode) {
        meshPreviewNode.classList.remove('mesh-preview-pulse');
      }
    }, 550);
  }

  function inferNetworkCause(data, hasNetworkPulse) {
    const causePayload = data && data.network_cause ? String(data.network_cause).trim() : '';
    if (causePayload === 'peer joined' || causePayload === 'relay path changed') {
      return causePayload;
    }

    if (hasNetworkPulse) {
      return 'peer count changed';
    }

    return '';
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

  function shouldPulseForChat(state) {
    const messages = sanitizeChatMessages(state);
    const latest = messages[0];
    const latestHash = latest && latest.hash ? `${latest.hash}` : null;
    const latestOrigin = latest ? latest.origin || latest.from || null : null;

    if (latestHash === null) {
      if (previousChatHash === null) {
        previousChatHash = latestHash;
      }
      return { changed: false, origin: latestOrigin };
    }

    if (previousChatHash === null) {
      previousChatHash = latestHash;
      return { changed: false, origin: latestOrigin };
    }

    if (latestHash !== previousChatHash) {
      previousChatHash = latestHash;
      return { changed: true, origin: latestOrigin };
    }

    return { changed: false, origin: latestOrigin };
  }

  function triggerChatPulse() {
    if (!chatCardNode) {
      return;
    }

    chatCardNode.classList.remove('card-chat-pulse');
    void chatCardNode.offsetWidth;
    chatCardNode.classList.add('card-chat-pulse');

    clearTimeout(chatPulseTimer);
    chatPulseTimer = setTimeout(() => {
      if (chatCardNode) {
        chatCardNode.classList.remove('card-chat-pulse');
      }
    }, 560);
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
  const sourceTypeClassCore = 'chat-source-indicator-core';
  const sourceTypeClassFallback = 'chat-source-indicator-fallback';
  const chatSendModeClassCore = 'chat-send-mode-core';
  const chatSendModeClassDemo = 'chat-send-mode-demo';
  const chatSendModeClassOffline = 'chat-send-mode-offline';
  const chatSendStatusClassError = 'chat-send-status-error';
  const chatSendStatusClassSuccess = 'chat-send-status-success';
  const healthCardNode = cardNodes.healthCard;
  const healthBannerNode = document.getElementById('health-banner');
  const healthPolicyNode = document.getElementById('health-policy-state');
  const healthSourceNode = document.getElementById('health-policy-source');
  const healthDotNode = document.getElementById('health-dot');
  const seedTargets = [];
  const cardNames = ['core', 'network', 'relay', 'ai', 'hash', 'events', 'liveflow', 'globalchat', 'integrity'];
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

    if (key === 'recent_chat_messages') {
      return;
    }

    if (key === 'recent_flow') {
      return;
    }

    if (key === 'last_event_hash' || key === 'event_type' || key === 'event_timestamp' || key === 'event_origin' || key === 'event_channel') {
      return;
    }

    cardNodes[key].textContent = value;
  }

  function describeChatSendMode(mode) {
    switch (mode) {
      case 'core':
        return 'send to core';
      case 'offline':
        return 'offline read-only';
      case 'demo':
        return 'demo fallback';
      case 'core_unavailable':
        return 'core send unavailable';
      case 'forbidden':
        return 'local only';
      case 'invalid':
        return 'invalid input';
      default:
        return String(mode || 'send state unknown').replace(/_/g, ' ');
    }
  }

  function setChatSendStatus(text, tone = '') {
    if (!chatSendStatusNode) {
      return;
    }

    chatSendStatusNode.textContent = text;
    chatSendStatusNode.classList.remove(chatSendStatusClassError, chatSendStatusClassSuccess);
    if (tone === 'error') {
      chatSendStatusNode.classList.add(chatSendStatusClassError);
    } else if (tone === 'success') {
      chatSendStatusNode.classList.add(chatSendStatusClassSuccess);
    }
  }

  function updateChatComposerState(chatSendMode = null) {
    const text = chatInputNode ? chatInputNode.value : '';
    const size = bytesize(text);
    const hasText = text && text.trim() !== '';
    const normalizedMode = chatSendMode ? String(chatSendMode) : null;
    const readOnly = normalizedMode === 'offline';

    if (chatByteCounterNode) {
      chatByteCounterNode.textContent = `${size} / 32 bytes`;
      chatByteCounterNode.classList.toggle('chat-byte-counter-invalid', size > 32);
    }

    if (chatSendBtnNode) {
      chatSendBtnNode.disabled = !hasText || size > 32 || readOnly;
      chatSendBtnNode.setAttribute('aria-disabled', chatSendBtnNode.disabled ? 'true' : 'false');
      chatSendBtnNode.title = readOnly ? 'Offline local state is read-only.' : 'Send message';
    }
  }

  function applyChatSendMode(mode) {
    if (!chatSendModeNode) {
      return;
    }

    const normalized = String(mode || 'unknown');
    const label = describeChatSendMode(normalized);

    chatSendModeNode.textContent = `send mode: ${label}`;
    chatSendModeNode.classList.remove(
      chatSendModeClassCore,
      chatSendModeClassDemo,
      chatSendModeClassOffline,
    );
    if (normalized === 'core') {
      chatSendModeNode.classList.add(chatSendModeClassCore);
    } else if (normalized === 'demo') {
      chatSendModeNode.classList.add(chatSendModeClassDemo);
    } else if (normalized === 'offline') {
      chatSendModeNode.classList.add(chatSendModeClassOffline);
    }
    updateChatComposerState(normalized);
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

    if (cardNodes.recent_flow) {
      const hasLiveFlowPulse = shouldPulseForLiveFlow(state);
      if (hasLiveFlowPulse) {
        triggerLiveFlowPulse();
      }
      cardNodes.recent_flow.innerHTML = formatLiveFlow(state, data, hasLiveFlowPulse);
    }

    const hasAiPulse = shouldPulseForAiInsight(state);
    if (hasAiPulse) {
      triggerAiPulse();
      setCardCause('ai', 'new insight detected');
    }

    if (cardNodes.ai_recent_insights) {
      cardNodes.ai_recent_insights.innerHTML = formatAiInsights(state, hasAiPulse);
    }

    const hasChatPulse = shouldPulseForChat(state);
    if (cardNodes.recent_chat_messages) {
      cardNodes.recent_chat_messages.innerHTML = formatChatMessages(state, data);
      if (hasChatPulse.changed) {
        triggerChatPulse();
        const chatHighlight = resolveChatOriginForPeerDot(hasChatPulse.origin, state.peers_count);
        if (chatHighlight && state && state.peers_count !== undefined) {
          renderMeshPreview(state.peers_count, chatHighlight);
        }
      }
    }

    const hasNetworkPulse = shouldPulseForNetwork(state);
    if (hasNetworkPulse) {
      triggerNetworkPulse();
      triggerMeshPulse();
      const networkCause = inferNetworkCause(data, true);
      if (networkCause) {
        setCardCause('network', networkCause);
      }
    } else if (hasInitializedNetworkState) {
      const networkCause = inferNetworkCause(data, false);
      if (networkCause) {
        setCardCause('network', networkCause);
      }
    }

    if (networkCauseHintNode) {
      const networkCause = inferNetworkCause(data, hasNetworkPulse);
      networkCauseHintNode.textContent = networkCause ? `network cause: ${networkCause}` : '';
    }

    if (!hasInitializedNetworkState) {
      hasInitializedNetworkState = true;
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

    if (sourceNode) {
      sourceNode.textContent = `mode: ${describeSurfaceMode(data.source_type, data.adapter_status)}`;
    }

    if (data && data.chat_send_mode) {
      applyChatSendMode(String(data.chat_send_mode));
    }

    if (chatSourceNode) {
      const sourceType = String(data && data.source_type ? data.source_type : 'unknown');
      const sourceIsCore = sourceType === 'core' || sourceType === 'file' || sourceType === 'sqlite';
      const label = describeChatSource(sourceType);

      chatSourceNode.textContent = `messages source: ${label}`;
      chatSourceNode.classList.remove(sourceTypeClassCore, sourceTypeClassFallback);
      chatSourceNode.classList.add(sourceIsCore ? sourceTypeClassCore : sourceTypeClassFallback);
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
        healthPolicyNode.textContent = describeSurfaceMode(sourceType, adapterStatus);
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
      if (!response.ok) {
        setChatSendStatus('Dashboard unavailable. Last view may be stale.', 'error');
        return;
      }
      const payload = await response.json();
      applyState(payload);
    } catch (_err) {
      setChatSendStatus('Dashboard unavailable. Last view may be stale.', 'error');
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

  async function simulate(action, extraPayload = {}) {
    const payload = Object.assign({ action }, extraPayload || {});
    try {
      const response = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!response.ok) return;
      const payload = await response.json();
      applyState(payload);
      await fetchHealth();
    } catch (_err) {
      // fail-closed on UI side: preserve old state silently
    }
  }

  function bytesize(value) {
    if (value === null || value === undefined) {
      return 0;
    }

    if (typeof window.TextEncoder === 'undefined') {
      return String(value).length;
    }

    return new TextEncoder().encode(String(value)).length;
  }

  function sendChatMessage() {
    if (!chatInputNode) {
      return;
    }

    const text = chatInputNode.value;
    if (!text || text.trim() === '') {
      setChatSendStatus('Enter a message before sending.', 'error');
      return;
    }

    if (bytesize(text) > 32) {
      setChatSendStatus('Message is over the 32-byte limit.', 'error');
      return;
    }

    setChatSendStatus('Sending message...');

    fetch('/api/chat/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    })
      .then(async (response) => {
        const payload = await response.json().catch(() => null);
        if (!response.ok || !payload || !payload.state) {
          if (payload && payload.chat_send_mode) {
            applyChatSendMode(String(payload.chat_send_mode));
          }
          if (payload && payload.error === 'offline_read_only') {
            setChatSendStatus('Offline local state is read-only.', 'error');
          } else if (payload && payload.error === 'local_only_route') {
            setChatSendStatus('Chat send is available only from this local machine.', 'error');
          } else if (payload && payload.error === 'core_chat_send_unavailable') {
            setChatSendStatus('Core send unavailable. No message was sent.', 'error');
          } else if (payload && payload.error === 'chat_message_too_long') {
            setChatSendStatus('Message is over the 32-byte limit.', 'error');
          } else if (payload && payload.error === 'chat_message_empty') {
            setChatSendStatus('Enter a message before sending.', 'error');
          } else {
            setChatSendStatus('Chat send failed. No message was sent.', 'error');
          }
          return;
        }
        applyState(payload);
        fetchHealth();
        chatInputNode.value = '';
        updateChatComposerState(payload.chat_send_mode || 'core');
        setChatSendStatus(
          payload.chat_send_mode === 'demo' ? 'Demo message added.' : 'Message sent to core.',
          'success',
        );
      })
      .catch(() => {
        applyChatSendMode('core_unavailable');
        setChatSendStatus('Chat send failed. Dashboard is unavailable.', 'error');
      });
  }

  document.getElementById('refresh-btn').addEventListener('click', () => {
    fetchStatus();
    fetchHealth();
  });
  document.querySelectorAll('.simulate-button').forEach((button) => {
    button.addEventListener('click', () => simulate(button.getAttribute('data-action')));
  });
  if (chatSendBtnNode) {
    chatSendBtnNode.addEventListener('click', sendChatMessage);
  }
  if (chatInputNode) {
    chatInputNode.addEventListener('input', () => updateChatComposerState());
    chatInputNode.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        sendChatMessage();
      }
    });
  }
  setInterval(() => {
    fetchStatus();
    fetchHealth();
  }, 3000);

  fetchStatus();
  fetchHealth();
  updateChatComposerState();
})();
