/**
 * MIRAGE Dashboard — Interactive Application Logic
 * ==================================================
 * Handles:
 *   - WebSocket connection & real-time updates
 *   - Attack Graph canvas rendering (force-directed layout)
 *   - Belief state display
 *   - Active decoys panel
 *   - Audit log streaming
 *   - User actions (trigger decision, simulate attack)
 */

// ============================================================
// Configuration
// ============================================================

const CONFIG = {
  API_BASE: window.location.hostname === '' || window.location.protocol === 'file:'
    ? 'http://localhost:8000'
    : window.location.origin,
  WS_BASE: window.location.hostname === '' || window.location.protocol === 'file:'
    ? 'ws://localhost:8000/ws'
    : `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`,
  RECONNECT_DELAY: 3000,
  GRAPH_PHYSICS: {
    repulsion: 3000,
    attraction: 0.008,
    damping: 0.88,
    centerGravity: 0.03,
    dt: 0.6,
  },
};

// ============================================================
// State
// ============================================================

const legacyApiKey = window.localStorage.getItem('mirage_api_key') || '';
const storedApiKey = window.sessionStorage.getItem('mirage_api_key') || legacyApiKey;
if (legacyApiKey) {
  window.sessionStorage.setItem('mirage_api_key', legacyApiKey);
  window.localStorage.removeItem('mirage_api_key');
}

const state = {
  ws: null,
  connected: false,
  graph: { nodes: [], edges: [] },
  beliefs: {},
  decoys: [],
  logs: [],
  showLabels: true,
  dragNode: null,
  mousePos: { x: 0, y: 0 },
  hoverNode: null,
  metrics: { events: 0, hosts: 0, decoys: 0 },
  apiKey: storedApiKey,
  authWarningShown: false,
};

// ============================================================
// DOM References
// ============================================================

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);
const escapeHTML = (value) => String(value)
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#039;');

const DOM = {
  canvas: $('#graph-canvas'),
  wsIndicator: $('#ws-indicator'),
  wsDot: null,
  wsText: null,
  metricEvents: null,
  metricHosts: null,
  metricDecoys: null,
  beliefBody: $('#belief-body'),
  decoysBody: $('#decoys-body'),
  logBody: $('#log-body'),
  tooltip: $('#node-tooltip'),
  tooltipTitle: $('#tooltip-title'),
  tooltipBody: $('#tooltip-body'),
  uptimeDisplay: $('#uptime-display'),
  apiKeyInput: $('#api-key-input'),
  apiUrl: $('#api-url code'),
};

function apiHeaders(headers = {}) {
  const result = { ...headers };
  if (state.apiKey) result['X-API-Key'] = state.apiKey;
  return result;
}

function apiFetch(path, options = {}) {
  return fetch(`${CONFIG.API_BASE}${path}`, {
    ...options,
    headers: apiHeaders(options.headers || {}),
  });
}

function websocketProtocols() {
  if (!state.apiKey) return [];
  const bytes = new TextEncoder().encode(state.apiKey);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded = btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
  return ['mirage', `mirage-key.${encoded}`];
}

function handleUnauthorized() {
  updateConnectionStatus('auth-required');
  if (!state.authWarningShown) {
    addLog('warning', 'API key required. Enter it in the bottom bar and click Apply key.');
    state.authWarningShown = true;
  }
}

// ============================================================
// WebSocket Connection
// ============================================================

function connectWebSocket() {
  if (state.ws && state.ws.readyState <= 1) return;

  const protocols = websocketProtocols();
  state.ws = protocols.length > 0
    ? new WebSocket(CONFIG.WS_BASE, protocols)
    : new WebSocket(CONFIG.WS_BASE);

  state.ws.onopen = () => {
    state.connected = true;
    updateConnectionStatus('connected');
    addLog('success', 'WebSocket connected to MIRAGE API');
  };

  state.ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleWSMessage(msg);
    } catch (e) {
      console.error('WS parse error:', e);
    }
  };

  state.ws.onclose = (event) => {
    state.connected = false;
    if (event.code === 4401) {
      handleUnauthorized();
      return;
    }
    updateConnectionStatus('disconnected');
    addLog('warning', 'WebSocket disconnected. Reconnecting…');
    setTimeout(connectWebSocket, CONFIG.RECONNECT_DELAY);
  };

  state.ws.onerror = () => {
    state.connected = false;
    updateConnectionStatus('disconnected');
  };
}

function handleWSMessage(msg) {
  switch (msg.type) {
    case 'init':
      if (msg.graph) {
        state.graph = msg.graph;
        state.decoys = msg.graph.active_defenses || [];
        initGraphLayout();
        renderGraph();
        renderDecoysPanel();
      }
      if (msg.status) updateMetrics(msg.status);
      break;

    case 'telemetry_update':
      handleTelemetryUpdate(msg.data);
      break;

    case 'batch_update':
      addLog('info', `Batch: ${msg.count} events from ${msg.hosts.join(', ')}`);
      for (const result of msg.results || []) handleTelemetryUpdate(result);
      break;

    case 'decision':
      handleDecisionUpdate(msg.data);
      break;

    case 'defenses_update':
      state.decoys = msg.data || [];
      if (msg.graph) {
        state.graph = msg.graph;
        initGraphLayout();
        renderGraph();
      }
      state.metrics.decoys = state.decoys.length;
      updateMetricDisplay('metric-decoys', state.metrics.decoys);
      renderDecoysPanel();
      break;

    case 'pong':
      break;

    default:
      console.log('Unknown WS message:', msg);
  }
}

function updateConnectionStatus(status) {
  const dot = DOM.wsIndicator.querySelector('.indicator__dot');
  const text = DOM.wsIndicator.querySelector('.indicator__text');
  dot.className = 'indicator__dot ' + status;
  text.textContent = status === 'connected'
    ? 'Connected'
    : status === 'disconnected'
      ? 'Disconnected'
      : status === 'auth-required'
        ? 'API Key Required'
        : 'Connecting…';
}

// ============================================================
// Telemetry & Belief Handling
// ============================================================

function handleTelemetryUpdate(data) {
  state.metrics.events = data.total_processed || state.metrics.events + 1;
  updateMetricDisplay('metric-events', state.metrics.events);

  // Update belief state
  state.beliefs[data.host] = {
    stage: data.dominant_stage,
    confidence: data.confidence,
    distribution: data.stage_distribution,
  };
  state.metrics.hosts = Object.keys(state.beliefs).length;
  updateMetricDisplay('metric-hosts', state.metrics.hosts);

  renderBeliefPanel();

  // Update graph node highlighting based on belief
  if (data.graph_belief_top5) {
    for (const node of state.graph.nodes) {
      const bv = data.graph_belief_top5[node.id];
      node.beliefHighlight = bv || 0;
    }
    renderGraph();
  }

  // Log the event
  const stageEmoji = getStageEmoji(data.dominant_stage);
  addLog('info', `${stageEmoji} ${data.host}: ${data.event_type} → ${data.dominant_stage} (${(data.confidence * 100).toFixed(0)}%)`);
}

function handleDecisionUpdate(data) {
  const action = data.action_type || 'NOOP';
  const label = data.target_node_label || data.target_label || '';
  addLog('danger', `Decision [${data.status || 'recommended'}]: ${action} → Node ${data.target_node ?? '—'} (${label})`);
  addLog('info', `Reason: ${data.reasoning || 'No action selected.'}`);
}

function getStageEmoji(stage) {
  const map = {
    'Recon': '🔍', 'Initial Access': '🚪', 'Discovery': '🗺️',
    'Lateral Movement': '↔️', 'Credential Access': '🔑',
    'Collection': '📦', 'Exfiltration': '📤', 'Unknown': '❓',
  };
  return map[stage] || '•';
}

// ============================================================
// Graph Rendering (Force-directed Canvas)
// ============================================================

let graphNodes = [];
let graphEdges = [];
let nodeById = new Map();

const LAYER_COLORS = {
  external:    { fill: '#2d3748', stroke: '#718096' },
  dmz:         { fill: '#2b4c7e', stroke: '#5b9bd5' },
  internal:    { fill: '#4a3560', stroke: '#9b59b6' },
  services:    { fill: '#1b4332', stroke: '#52b788' },
  credentials: { fill: '#5c3d1e', stroke: '#e09f3e' },
  critical:    { fill: '#5c1a1a', stroke: '#e74c3c' },
  data:        { fill: '#1a3c5c', stroke: '#3498db' },
  sink:        { fill: '#1a1a2e', stroke: '#444' },
  unknown:     { fill: '#2d3748', stroke: '#718096' },
};

function initGraphLayout() {
  const canvas = DOM.canvas;
  const W = canvas.parentElement.clientWidth || 900;
  const H = canvas.parentElement.clientHeight || 600;
  canvas.width = W;
  canvas.height = H;
  nodeById = new Map(state.graph.nodes.map(node => [node.id, node]));

  // Initialize node positions using layer-based layout
  const layerOrder = ['external', 'dmz', 'services', 'internal', 'credentials', 'critical', 'data', 'sink'];
  const layerGroups = {};
  state.graph.nodes.forEach(n => {
    const layer = n.layer || 'unknown';
    if (!layerGroups[layer]) layerGroups[layer] = [];
    layerGroups[layer].push(n);
  });

  const usedLayers = layerOrder.filter(l => (layerGroups[l] || []).length > 0);
  usedLayers.forEach((layer, li) => {
    const group = layerGroups[layer] || [];
    const yBase = (li + 0.5) / usedLayers.length * H;
    group.forEach((n, ni) => {
      const xBase = (ni + 1) / (group.length + 1) * W;
      n.x = xBase + (Math.random() - 0.5) * 40;
      n.y = yBase + (Math.random() - 0.5) * 30;
      n.vx = 0;
      n.vy = 0;
      n.radius = n.is_goal ? 18 : n.is_decoy ? 16 : n.is_sink ? 10 : 14;
      n.beliefHighlight = 0;
    });
  });

  // Handle nodes without layer
  state.graph.nodes.forEach(n => {
    if (n.x === undefined) {
      n.x = W / 2 + (Math.random() - 0.5) * 200;
      n.y = H / 2 + (Math.random() - 0.5) * 200;
      n.vx = 0;
      n.vy = 0;
      n.radius = 14;
      n.beliefHighlight = 0;
    }
  });

  // Run physics simulation for initial layout
  const layoutIterations = state.graph.nodes.length <= 200 ? 120 : 20;
  for (let i = 0; i < layoutIterations; i++) {
    stepPhysics();
  }

  renderGraph();
}

function stepPhysics() {
  const nodes = state.graph.nodes;
  const edges = state.graph.edges;
  const canvas = DOM.canvas;
  const W = canvas.width;
  const H = canvas.height;
  const P = CONFIG.GRAPH_PHYSICS;

  // Exact repulsion for small graphs; bounded sampling for large graphs.
  const applyRepulsion = (i, j) => {
      const dx = nodes[j].x - nodes[i].x;
      const dy = nodes[j].y - nodes[i].y;
      const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const force = P.repulsion / (dist * dist);
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      nodes[i].vx -= fx;
      nodes[i].vy -= fy;
      nodes[j].vx += fx;
      nodes[j].vy += fy;
  };
  if (nodes.length <= 250) {
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        applyRepulsion(i, j);
      }
    }
  } else {
    const samplesPerNode = 24;
    for (let i = 0; i < nodes.length; i++) {
      for (let sample = 0; sample < samplesPerNode; sample++) {
        const j = (i + 1 + sample * 97) % nodes.length;
        if (j !== i) applyRepulsion(i, j);
      }
    }
  }

  // Attraction (edges)
  for (const edge of edges) {
    const src = nodeById.get(edge.source);
    const tgt = nodeById.get(edge.target);
    if (!src || !tgt) continue;
    const dx = tgt.x - src.x;
    const dy = tgt.y - src.y;
    const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
    const force = dist * P.attraction;
    src.vx += (dx / dist) * force;
    src.vy += (dy / dist) * force;
    tgt.vx -= (dx / dist) * force;
    tgt.vy -= (dy / dist) * force;
  }

  // Center gravity
  for (const n of nodes) {
    n.vx += (W / 2 - n.x) * P.centerGravity;
    n.vy += (H / 2 - n.y) * P.centerGravity;
  }

  // Integrate with damping
  for (const n of nodes) {
    n.vx *= P.damping;
    n.vy *= P.damping;
    n.x += n.vx * P.dt;
    n.y += n.vy * P.dt;
    // Bound to canvas
    n.x = Math.max(30, Math.min(W - 30, n.x));
    n.y = Math.max(30, Math.min(H - 30, n.y));
  }
}

function renderGraph() {
  const canvas = DOM.canvas;
  const ctx = canvas.getContext('2d');
  const W = canvas.width;
  const H = canvas.height;

  ctx.clearRect(0, 0, W, H);

  // Background grid
  ctx.strokeStyle = 'hsla(220, 15%, 20%, 0.3)';
  ctx.lineWidth = 0.5;
  for (let x = 0; x < W; x += 50) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
  }
  for (let y = 0; y < H; y += 50) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  }

  const nodes = state.graph.nodes;
  const edges = state.graph.edges;

  // Draw edges
  for (const edge of edges) {
    const src = nodeById.get(edge.source);
    const tgt = nodeById.get(edge.target);
    if (!src || !tgt) continue;

    ctx.beginPath();
    ctx.moveTo(src.x, src.y);
    ctx.lineTo(tgt.x, tgt.y);
    ctx.strokeStyle = `hsla(185, 40%, 50%, ${0.15 + edge.probability * 0.25})`;
    ctx.lineWidth = 1 + edge.probability * 1.5;
    ctx.stroke();

    // Arrowhead
    const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
    const arrowLen = 8;
    const midX = (src.x + tgt.x) / 2;
    const midY = (src.y + tgt.y) / 2;
    ctx.beginPath();
    ctx.moveTo(midX, midY);
    ctx.lineTo(midX - arrowLen * Math.cos(angle - 0.4), midY - arrowLen * Math.sin(angle - 0.4));
    ctx.moveTo(midX, midY);
    ctx.lineTo(midX - arrowLen * Math.cos(angle + 0.4), midY - arrowLen * Math.sin(angle + 0.4));
    ctx.stroke();
  }

  // Draw nodes
  for (const n of nodes) {
    const colors = LAYER_COLORS[n.layer] || LAYER_COLORS.unknown;
    const r = n.radius || 14;

    // Belief highlight glow
    if (n.beliefHighlight > 0.05) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 8, 0, Math.PI * 2);
      ctx.fillStyle = `hsla(38, 90%, 58%, ${n.beliefHighlight * 0.5})`;
      ctx.fill();
    }

    // Node circle
    ctx.beginPath();
    ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    ctx.fillStyle = colors.fill;
    ctx.fill();
    ctx.strokeStyle = n.is_decoy ? '#52b788' : n.is_goal ? '#e74c3c' : colors.stroke;
    ctx.lineWidth = n.is_goal || n.is_decoy ? 2.5 : 1.5;
    ctx.stroke();

    // Decoy indicator
    if (n.is_decoy) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 3, 0, Math.PI * 2);
      ctx.strokeStyle = 'hsla(155, 70%, 55%, 0.4)';
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 3]);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Goal marker
    if (n.is_goal) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 4, 0, Math.PI * 2);
      ctx.strokeStyle = 'hsla(0, 78%, 60%, 0.4)';
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 2]);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Hover highlight
    if (state.hoverNode && state.hoverNode.id === n.id) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
      ctx.strokeStyle = 'hsla(185, 85%, 55%, 0.6)';
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    // Label
    if (state.showLabels) {
      ctx.font = '500 10px Inter, sans-serif';
      ctx.fillStyle = 'hsla(220, 20%, 85%, 0.9)';
      ctx.textAlign = 'center';
      ctx.fillText(n.label, n.x, n.y + r + 14);
    }

    // Node ID
    ctx.font = '600 9px JetBrains Mono, monospace';
    ctx.fillStyle = 'hsla(220, 20%, 95%, 0.9)';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(n.id, n.x, n.y);
  }
}

// ============================================================
// Canvas Interaction (Drag, Hover, Tooltip)
// ============================================================

function setupCanvasInteraction() {
  const canvas = DOM.canvas;

  canvas.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    state.mousePos = { x: mx, y: my };

    if (state.dragNode) {
      state.dragNode.x = mx;
      state.dragNode.y = my;
      state.dragNode.vx = 0;
      state.dragNode.vy = 0;
      renderGraph();
      return;
    }

    // Hover detection
    let found = null;
    for (const n of state.graph.nodes) {
      const dx = mx - n.x;
      const dy = my - n.y;
      if (dx * dx + dy * dy < (n.radius + 4) * (n.radius + 4)) {
        found = n;
        break;
      }
    }

    if (found !== state.hoverNode) {
      state.hoverNode = found;
      renderGraph();
      if (found) {
        showTooltip(found, e.clientX, e.clientY);
      } else {
        hideTooltip();
      }
    }
  });

  canvas.addEventListener('mousedown', (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    for (const n of state.graph.nodes) {
      const dx = mx - n.x;
      const dy = my - n.y;
      if (dx * dx + dy * dy < (n.radius + 4) * (n.radius + 4)) {
        state.dragNode = n;
        canvas.style.cursor = 'grabbing';
        break;
      }
    }
  });

  canvas.addEventListener('mouseup', () => {
    state.dragNode = null;
    DOM.canvas.style.cursor = 'grab';
  });

  canvas.addEventListener('mouseleave', () => {
    state.dragNode = null;
    state.hoverNode = null;
    hideTooltip();
    DOM.canvas.style.cursor = 'grab';
  });
}

function showTooltip(node, clientX, clientY) {
  const tooltip = DOM.tooltip;
  DOM.tooltipTitle.textContent = `Node ${node.id}: ${node.label}`;

  const typeIcon = node.is_goal ? '🎯 True Goal' : node.is_decoy ? '🍯 Decoy' : node.is_sink ? '⏹️ Sink' : '🖥️ Asset';
  const belief = state.beliefs[node.label] || null;

  let bodyHTML = `
    <div class="tooltip-row"><span class="label">Type</span><span class="value">${typeIcon}</span></div>
    <div class="tooltip-row"><span class="label">Layer</span><span class="value">${escapeHTML(node.layer)}</span></div>
    <div class="tooltip-row"><span class="label">Asset</span><span class="value">${escapeHTML(node.asset_type)}</span></div>
    <div class="tooltip-row"><span class="label">Value</span><span class="value">${Number(node.value || 0).toFixed(1)}</span></div>
    <div class="tooltip-row"><span class="label">Belief</span><span class="value">${Number(node.belief || 0).toFixed(3)}</span></div>
  `;
  if (belief) {
    bodyHTML += `<div class="tooltip-row"><span class="label">Stage</span><span class="value">${escapeHTML(belief.stage)}</span></div>`;
  }

  DOM.tooltipBody.innerHTML = bodyHTML;
  tooltip.style.display = 'block';

  const rect = DOM.canvas.parentElement.getBoundingClientRect();
  tooltip.style.left = (clientX - rect.left + 16) + 'px';
  tooltip.style.top = (clientY - rect.top - 10) + 'px';
}

function hideTooltip() {
  DOM.tooltip.style.display = 'none';
}

// ============================================================
// Panel Rendering
// ============================================================

function renderBeliefPanel() {
  const container = DOM.beliefBody;
  if (Object.keys(state.beliefs).length === 0) {
    container.innerHTML = '<div class="empty-state">Waiting for telemetry data…</div>';
    return;
  }

  let html = '';
  for (const [host, data] of Object.entries(state.beliefs)) {
    html += `
      <div class="belief-host">
        <div class="belief-host__name">${escapeHTML(host)}</div>
        <div class="belief-host__stage">
          <span>${getStageEmoji(data.stage)} ${escapeHTML(data.stage)}</span>
          <span>${(data.confidence * 100).toFixed(0)}%</span>
        </div>
        <div class="belief-host__bar">
          <div class="belief-host__bar-fill" style="width: ${data.confidence * 100}%"></div>
        </div>
      </div>
    `;
  }
  container.innerHTML = html;
}

function renderDecoysPanel() {
  const container = DOM.decoysBody;
  if (state.decoys.length === 0) {
    container.innerHTML = '<div class="empty-state">No active deception actions</div>';
    return;
  }

  let html = '';
  const icons = {
    'deploy_decoy_database': '🗄️', 'deploy_decoy_router': '📡',
    'scatter_honey_credential': '🔑', 'increase_edge_cost': '🔥',
  };
  for (const d of state.decoys) {
    const type = d.action_type || d.type;
    const node = d.target_node ?? d.node;
    const label = d.target_label || d.label;
    const icon = icons[type] || '🛡️';
    html += `
      <div class="decoy-item">
        <div class="decoy-item__icon">${icon}</div>
        <div class="decoy-item__info">
          <div class="decoy-item__type">${escapeHTML(type)}</div>
          <div class="decoy-item__node">Node ${escapeHTML(node)} — ${escapeHTML(label)}</div>
        </div>
        <span class="decoy-item__status active">Active</span>
      </div>
    `;
  }
  container.innerHTML = html;
}

function updateMetricDisplay(id, value) {
  const el = document.querySelector(`#${id} .metric__value`);
  if (el) el.textContent = typeof value === 'number' ? value.toLocaleString() : value;
}

function updateMetrics(status) {
  state.metrics.events = status.total_events_processed || 0;
  state.metrics.hosts = status.tracked_hosts || 0;
  state.metrics.decoys = status.active_decoys || 0;
  updateMetricDisplay('metric-events', state.metrics.events);
  updateMetricDisplay('metric-hosts', state.metrics.hosts);
  updateMetricDisplay('metric-decoys', state.metrics.decoys);
  if (DOM.uptimeDisplay) {
    const mins = Math.floor((status.uptime_seconds || 0) / 60);
    DOM.uptimeDisplay.textContent = `Uptime: ${mins}m`;
  }
}

// ============================================================
// Audit Log
// ============================================================

function addLog(level, message) {
  const now = new Date();
  const ts = now.toLocaleTimeString('en-GB', { hour12: false });

  state.logs.push({ level, message, ts });
  if (state.logs.length > 200) state.logs.shift();

  const container = DOM.logBody;
  // Remove empty state
  const empty = container.querySelector('.empty-state');
  if (empty) empty.remove();

  const entry = document.createElement('div');
  entry.className = `log-entry ${level}`;
  const timeSpan = document.createElement('span');
  timeSpan.className = 'log-entry__time';
  timeSpan.textContent = ts;
  const messageSpan = document.createElement('span');
  messageSpan.className = 'log-entry__msg';
  messageSpan.textContent = message;
  entry.append(timeSpan, messageSpan);
  container.appendChild(entry);

  // Auto-scroll to bottom
  container.scrollTop = container.scrollHeight;

  // Limit DOM entries
  while (container.children.length > 150) {
    container.removeChild(container.firstChild);
  }
}

// ============================================================
// Button Actions
// ============================================================

function setupButtonHandlers() {
  // Trigger Decision
  $('#btn-trigger-decision')?.addEventListener('click', async () => {
    const button = $('#btn-trigger-decision');
    button.disabled = true;
    addLog('info', 'Triggering decision engine…');
    try {
      const res = await apiFetch('/api/decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deploy: true }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      addLog('success', `Decision: ${data.action_type} → Node ${data.target_node}`);
    } catch (e) {
      addLog('danger', `Decision trigger failed: ${e.message}`);
    } finally {
      button.disabled = false;
    }
  });

  // Simulate Attack
  $('#btn-simulate-attack')?.addEventListener('click', async () => {
    addLog('warning', 'Simulating lateral movement attack…');

    const events = [
      { source_host: 'attacker_pc', dest_host: '192.168.1.10', event_type: 'port_scan', port: 445 },
      { source_host: 'attacker_pc', dest_host: '192.168.1.10', event_type: 'port_scan', port: 3389 },
      { source_host: 'attacker_pc', dest_host: '192.168.1.1', event_type: 'login_attempt', username: 'admin', success: false },
      { source_host: 'attacker_pc', dest_host: '192.168.1.1', event_type: 'login_attempt', username: 'admin', success: false },
      { source_host: 'attacker_pc', dest_host: '192.168.1.1', event_type: 'login_attempt', username: 'admin', success: true },
      { source_host: 'attacker_pc', dest_host: '192.168.1.5', event_type: 'smb_connect' },
      { source_host: 'attacker_pc', dest_host: '192.168.1.6', event_type: 'smb_connect' },
      { source_host: 'attacker_pc', dest_host: '192.168.1.7', event_type: 'rdp_connect' },
      { source_host: 'attacker_pc', dest_host: '192.168.1.8', event_type: 'credential_use', username: 'svc_account' },
    ];

    for (const ev of events) {
      try {
        const response = await apiFetch('/api/telemetry', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(ev),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        await new Promise(r => setTimeout(r, 300));
      } catch (e) {
        addLog('danger', `Failed to send event: ${e.message}`);
        break;
      }
    }
    addLog('success', 'Attack simulation complete');
  });

  // Refresh Graph
  $('#btn-refresh-graph')?.addEventListener('click', async () => {
    try {
      const res = await apiFetch('/api/graph');
      if (res.status === 401) {
        handleUnauthorized();
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      state.graph = await res.json();
      state.decoys = state.graph.active_defenses || [];
      initGraphLayout();
      renderGraph();
      renderDecoysPanel();
      addLog('info', 'Graph refreshed');
    } catch (e) {
      addLog('danger', `Graph refresh failed: ${e.message}`);
    }
  });

  // Toggle Labels
  $('#btn-toggle-labels')?.addEventListener('click', () => {
    state.showLabels = !state.showLabels;
    renderGraph();
  });

  // Reset View
  $('#btn-reset-view')?.addEventListener('click', () => {
    initGraphLayout();
    renderGraph();
    addLog('info', 'Graph view reset');
  });

  // Clear Log
  $('#btn-clear-log')?.addEventListener('click', () => {
    state.logs = [];
    DOM.logBody.innerHTML = '<div class="empty-state">No events yet</div>';
  });

  $('#btn-save-api-key')?.addEventListener('click', () => {
    state.apiKey = DOM.apiKeyInput.value.trim();
    state.authWarningShown = false;
    if (state.apiKey) {
      window.sessionStorage.setItem('mirage_api_key', state.apiKey);
    } else {
      window.sessionStorage.removeItem('mirage_api_key');
    }
    if (state.ws) {
      state.ws.onclose = null;
      state.ws.close();
      state.ws = null;
    }
    updateConnectionStatus('connecting');
    loadGraphFromAPI();
    connectWebSocket();
  });
}

// ============================================================
// Fallback: Load graph from API if no WebSocket
// ============================================================

async function loadGraphFromAPI() {
  try {
    const res = await apiFetch('/api/graph');
    if (res.status === 401) {
      handleUnauthorized();
      return;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    state.graph = await res.json();
    state.decoys = state.graph.active_defenses || [];
    initGraphLayout();
    renderGraph();
    renderDecoysPanel();
    addLog('info', `Graph loaded: ${state.graph.nodes.length} nodes, ${state.graph.edges.length} edges`);
  } catch (error) {
    // API not available — load demo graph
    addLog('warning', `API graph unavailable (${error.message}); loading demo graph`);
    loadDemoGraph();
  }
}

function loadDemoGraph() {
  state.graph = {
    nodes: [
      { id: 0,  label: 'Internet',     layer: 'external',    asset_type: 'entry',       is_real: true,  value: 0.0, belief: 0.07, is_goal: false, is_decoy: false, is_sink: false },
      { id: 1,  label: 'WebServer',    layer: 'dmz',         asset_type: 'web_server',  is_real: true,  value: 0.2, belief: 0.07, is_goal: false, is_decoy: false, is_sink: false },
      { id: 2,  label: 'MailServer',   layer: 'dmz',         asset_type: 'mail_server', is_real: true,  value: 0.2, belief: 0.07, is_goal: false, is_decoy: false, is_sink: false },
      { id: 3,  label: 'WS_Eng',      layer: 'internal',    asset_type: 'workstation', is_real: true,  value: 0.3, belief: 0.07, is_goal: false, is_decoy: false, is_sink: false },
      { id: 4,  label: 'WS_Finance',  layer: 'internal',    asset_type: 'workstation', is_real: true,  value: 0.4, belief: 0.07, is_goal: false, is_decoy: false, is_sink: false },
      { id: 5,  label: 'WS_IT',       layer: 'internal',    asset_type: 'workstation', is_real: true,  value: 0.3, belief: 0.07, is_goal: false, is_decoy: false, is_sink: false },
      { id: 6,  label: 'FileShare',   layer: 'services',    asset_type: 'file_share',  is_real: true,  value: 0.4, belief: 0.07, is_goal: false, is_decoy: false, is_sink: false },
      { id: 7,  label: 'DNS_Server',  layer: 'services',    asset_type: 'dns_server',  is_real: true,  value: 0.3, belief: 0.07, is_goal: false, is_decoy: false, is_sink: false },
      { id: 8,  label: 'AdminCred',   layer: 'credentials', asset_type: 'credential',  is_real: true,  value: 0.6, belief: 0.07, is_goal: false, is_decoy: false, is_sink: false },
      { id: 9,  label: 'SvcCred',     layer: 'credentials', asset_type: 'credential',  is_real: true,  value: 0.5, belief: 0.07, is_goal: false, is_decoy: false, is_sink: false },
      { id: 10, label: 'Database_REAL', layer: 'data',       asset_type: 'database',    is_real: true,  value: 1.0, belief: 0.07, is_goal: true,  is_decoy: false, is_sink: false },
      { id: 11, label: 'Database_FAKE', layer: 'data',       asset_type: 'decoy_db',    is_real: false, value: 0.0, belief: 0.07, is_goal: false, is_decoy: true,  is_sink: false },
      { id: 12, label: 'FakeRouter',  layer: 'services',    asset_type: 'decoy_router',is_real: false, value: 0.0, belief: 0.07, is_goal: false, is_decoy: true,  is_sink: false },
      { id: 13, label: 'DomainCtrl',  layer: 'critical',    asset_type: 'dc',          is_real: true,  value: 0.9, belief: 0.07, is_goal: false, is_decoy: false, is_sink: false },
      { id: 14, label: 'Sink',        layer: 'sink',        asset_type: 'sink',        is_real: true,  value: 0.0, belief: 0.0,  is_goal: false, is_decoy: false, is_sink: true  },
    ],
    edges: [
      { source: 0, target: 1,  action: 'exploit_web', probability: 0.75 },
      { source: 0, target: 2,  action: 'phish_email', probability: 0.65 },
      { source: 1, target: 3,  action: 'smb_move',    probability: 0.55 },
      { source: 1, target: 4,  action: 'rdp_move',    probability: 0.50 },
      { source: 2, target: 5,  action: 'smb_move',    probability: 0.55 },
      { source: 3, target: 8,  action: 'cred_dump',   probability: 0.65 },
      { source: 4, target: 9,  action: 'cred_dump',   probability: 0.70 },
      { source: 5, target: 6,  action: 'smb_move',    probability: 0.55 },
      { source: 6, target: 9,  action: 'cred_dump',   probability: 0.60 },
      { source: 6, target: 12, action: 'rdp_move',    probability: 0.25 },
      { source: 8, target: 13, action: 'dc_attack',   probability: 0.80 },
      { source: 9, target: 10, action: 'db_access',   probability: 0.55 },
      { source: 9, target: 11, action: 'db_access',   probability: 0.45 },
      { source: 13,target: 10, action: 'db_access',   probability: 0.90 },
    ],
  };
  initGraphLayout();
  renderGraph();
  addLog('info', 'Demo graph loaded (API offline — standalone mode)');
}

// ============================================================
// Canvas Resize Handler
// ============================================================

function handleResize() {
  const container = DOM.canvas.parentElement;
  if (container) {
    const oldWidth = Math.max(1, DOM.canvas.width);
    const oldHeight = Math.max(1, DOM.canvas.height);
    const newWidth = Math.max(1, container.clientWidth);
    const newHeight = Math.max(1, container.clientHeight);
    for (const node of state.graph.nodes) {
      node.x = (node.x || oldWidth / 2) * newWidth / oldWidth;
      node.y = (node.y || oldHeight / 2) * newHeight / oldHeight;
    }
    DOM.canvas.width = newWidth;
    DOM.canvas.height = newHeight;
    renderGraph();
  }
}

// ============================================================
// Initialization
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
  DOM.apiKeyInput.value = state.apiKey;
  DOM.apiUrl.textContent = CONFIG.API_BASE;
  setupCanvasInteraction();
  setupButtonHandlers();
  window.addEventListener('resize', handleResize);

  // Try connecting to API
  loadGraphFromAPI();
  connectWebSocket();

  // Periodic status update
  setInterval(async () => {
    try {
      const res = await apiFetch('/api/status');
      if (res.status === 401) {
        handleUnauthorized();
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      updateMetrics(await res.json());
    } catch (error) {
      if (state.connected) {
        addLog('warning', `Status refresh failed: ${error.message}`);
      }
    }
  }, 10000);
});
