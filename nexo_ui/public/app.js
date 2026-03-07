(function() {
  const stateNodes = {
    system_status: document.getElementById('meta-system_status'),
    peers_count: document.getElementById('meta-peers_count'),
    relay_status: document.getElementById('meta-relay_status'),
    ai_last_insight: document.getElementById('meta-ai_last_insight'),
    recent_event_hash: document.getElementById('meta-recent_event_hash'),
    last_sync: document.getElementById('meta-last_sync'),
  };

  const cardNodes = {
    system_status: document.getElementById('value-system_status'),
    peers_count: document.getElementById('value-peers_count'),
    relay_status: document.getElementById('value-relay_status'),
    ai_last_insight: document.getElementById('value-ai_last_insight'),
    recent_event_hash: document.getElementById('value-recent_event_hash'),
  };

  const metaLabel = {
    system_status: 'system_status',
    peers_count: 'peers_count',
    relay_status: 'relay_status',
    ai_last_insight: 'ai_last_insight',
    recent_event_hash: 'recent_event_hash',
    last_sync: 'last_sync',
  };

  const seedTargets = [];
  for (let i = 0; i < 5; i++) {
    const cardName = ['core', 'network', 'relay', 'ai', 'hash'][i];
    const element = document.getElementById(`card-${cardName === 'core' ? 'core' : cardName === 'network' ? 'network' : cardName === 'relay' ? 'relay' : cardName === 'ai' ? 'ai' : 'hash'}`);
    if (element) {
      seedTargets.push(element);
    }
  }

  function applyState(data) {
    const state = data.state;
    const labels = {
      system_status: 'system_status',
      peers_count: `Peers: ${state.peers_count}`,
      relay_status: state.relay_status,
      ai_last_insight: state.ai_last_insight,
      recent_event_hash: state.recent_event_hash,
    };

    for (const key of Object.keys(state)) {
      if (stateNodes[key]) {
        const value = state[key];
        stateNodes[key].textContent = `${metaLabel[key]}: ${value}`;
      }
      if (cardNodes[key]) {
        cardNodes[key].textContent = labels[key] || `${key}: ${state[key]}`;
      }
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

    if (data.last_updated) {
      const out = document.getElementById('last-updated');
      out.textContent = data.last_updated;
    }
  }

  async function fetchStatus() {
    try {
      const response = await fetch('/api/status');
      if (!response.ok) {
        return;
      }
      const payload = await response.json();
      applyState(payload);
    } catch (_err) {
      // fail-closed on UI side: preserve old state silently
    }
  }

  document.getElementById('refresh-btn').addEventListener('click', fetchStatus);
  setInterval(fetchStatus, 3000);
})();
