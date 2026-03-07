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
    health: document.getElementById('value-health'),
    healthCard: document.getElementById('card-integrity'),
  };

  const metaLabel = {
    system_status: 'system_status',
    peers_count: 'peers_count',
    relay_status: 'relay_status',
    ai_last_insight: 'ai_last_insight',
    recent_event_hash: 'recent_event_hash',
    last_sync: 'last_sync',
  };

  const labelByKey = {
    system_status: 'system_status',
    peers_count: 'Peers',
    relay_status: 'Relay',
    ai_last_insight: 'AI',
    recent_event_hash: 'Hash Pulse',
  };

  const sourceNode = document.getElementById('data-source');
  const healthCardNode = cardNodes.healthCard;
  const seedTargets = [];
  const cardNames = ['core', 'network', 'relay', 'ai', 'hash', 'integrity'];
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

    if (key === 'ai_last_insight') {
      cardNodes[key].textContent = `${labelByKey[key]}: ${value}`;
      return;
    }

    if (key === 'recent_event_hash') {
      cardNodes[key].textContent = `${labelByKey[key]}: ${value}`;
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

  function applyHealth(data) {
    if (!cardNodes.health) {
      return;
    }

    cardNodes.health.innerHTML = `
      source: ${data.data_source}<br />
      adapter_status: ${data.adapter_status}<br />
      source_type: ${data.source_type}<br />
      ui_status: ${data.ui_status}<br />
      last_updated: ${data.last_updated}
    `;

    if (healthCardNode) {
      if (data.ui_status !== 'healthy') {
        healthCardNode.classList.add('card-health-warning');
      } else {
        healthCardNode.classList.remove('card-health-warning');
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
      if (!response.ok) return;
      const payload = await response.json();
      applyHealth(payload);
    } catch (_err) {
      // fail-closed on UI side: preserve old state silently
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
