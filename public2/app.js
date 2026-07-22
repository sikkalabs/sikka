(function () {
  'use strict';

  // Application State
  const state = {
    pollHandle: null,
    tipsLoaded: false,
    tips: [],
    overview: {
      torNetwork: "Loading...",
      publicURL: "Loading...",
      nodeAddress: "Loading...",
      nodeMessage: "Loading...",
      softwareVersion: "--",
      dagSize: "--",
      tipCount: "--",
      maxDepth: "--",
      knownNodes: "--",
      submitPow: "--",
      submitPowNote: "Loading...",
    },
    searchFeedback: "",
    searchFeedbackKind: "",
    peerPending: false,
    peerFeedbackMessage: "",
    peerFeedbackKind: "",
    knownPeersList: [],
    featuredPeer: "",
  };

  // DOM Elements
  const el = {
    searchForm: document.getElementById('searchForm'),
    searchInput: document.getElementById('searchInput'),
    searchFeedback: document.getElementById('searchFeedback'),
    
    peerForm: document.getElementById('peerForm'),
    peerInput: document.getElementById('peerInput'),
    peerBtn: document.getElementById('peerBtn'),
    peerFeedback: document.getElementById('peerFeedback'),

    dagSize: document.getElementById('metricDagSize'),
    maxDepth: document.getElementById('metricMaxDepth'),
    submitPow: document.getElementById('metricSubmitPow'),
    submitPowNote: document.getElementById('metricSubmitPowNote'),
    softwareVersion: document.getElementById('metricSoftwareVersion'),
    
    tipsFeed: document.getElementById('tipsFeed'),
    tipsBadge: document.getElementById('tipsBadge'),
    
    torNetwork: document.getElementById('topoTorNetwork'),
    publicURL: document.getElementById('topoPublicURL'),
    nodeAddress: document.getElementById('topoNodeAddress'),
    nodeAddressItem: document.getElementById('topoNodeAddressItem'),
    nodeMessage: document.getElementById('topoNodeMessage'),
    
    knownNodesBadge: document.getElementById('knownNodesBadge'),
    knownNodesDesc: document.getElementById('knownNodesDesc'),

    featuredPeerContainer: document.getElementById('featuredPeerContainer'),
    featuredPeerUrl: document.getElementById('featuredPeerUrl'),
    shufflePeerBtn: document.getElementById('shufflePeerBtn'),
  };

  // Helper Functions
  async function fetchJSON(path) {
    const response = await fetch(path);
    if (!response.ok) {
      throw new Error(path + " returned HTTP " + response.status);
    }
    return response.json();
  }

  function formatTorNetwork(torStatus, torHealth) {
    if (torStatus.control_connected !== true) {
      return "Control connection unavailable";
    }
    const health = torHealth ? torHealth.charAt(0).toUpperCase() + torHealth.slice(1) : "Unknown";
    const parts = [health];
    parts.push(torStatus.circuit_established ? "circuit ready" : "no circuit yet");
    if (torStatus.control_error) {
      parts.push(torStatus.control_error);
    }
    return parts.join(" · ");
  }

  async function fetchNetworkPowQuote(tips) {
    if (!Array.isArray(tips) || !tips.length) {
      return null;
    }
    const parents = tips.length >= 2 ? tips.slice(0, 2) : [tips[0], tips[0]];
    const response = await fetch("/v1/tx/pow-quote", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        parents,
        timestamp: Math.floor(Date.now() / 1000),
      }),
    });

    if (!response.ok) {
      throw new Error("/v1/tx/pow-quote returned HTTP " + response.status);
    }

    const quote = await response.json();
    const requiredBits = Number(quote.required_bits);
    if (!Number.isFinite(requiredBits)) {
      throw new Error("invalid network pow quote");
    }

    return {
      requiredBits,
      recentCount: Number(quote.recent_count ?? NaN),
      windowSeconds: Number(quote.window_seconds ?? NaN),
      overrideBits: Number(quote.override_bits ?? NaN),
    };
  }

  function applySubmitPow(quote) {
    if (!quote || !Number.isFinite(quote.requiredBits)) {
      state.overview.submitPow = "--";
      state.overview.submitPowNote = "Unavailable";
      return;
    }

    state.overview.submitPow = quote.requiredBits + " bits";
    if (Number.isFinite(quote.overrideBits) && quote.overrideBits > 0) {
      state.overview.submitPowNote = "Fixed override";
      return;
    }
    if (Number.isFinite(quote.recentCount) && Number.isFinite(quote.windowSeconds)) {
      state.overview.submitPowNote = quote.recentCount + " recent tx / " + quote.windowSeconds + "s window";
      return;
    }
    state.overview.submitPowNote = "Live network quote";
  }

  // Update DOM Views
  function updateUI() {
    if (el.dagSize) el.dagSize.textContent = state.overview.dagSize;
    if (el.maxDepth) el.maxDepth.textContent = state.overview.maxDepth;
    if (el.submitPow) el.submitPow.textContent = state.overview.submitPow;
    if (el.submitPowNote) el.submitPowNote.textContent = state.overview.submitPowNote;
    if (el.softwareVersion) el.softwareVersion.textContent = "v" + state.overview.softwareVersion;
    
    if (el.torNetwork) el.torNetwork.textContent = state.overview.torNetwork;
    if (el.publicURL) el.publicURL.textContent = state.overview.publicURL;
    if (el.nodeMessage) el.nodeMessage.textContent = state.overview.nodeMessage;

    // Node address
    const addr = String(state.overview.nodeAddress || "").trim().toLowerCase();
    if (el.nodeAddressItem && el.nodeAddress) {
      if (addr && addr !== "loading..." && addr !== "unavailable" && addr !== "--") {
        el.nodeAddressItem.style.display = "block";
        if (/^sikka1[023456789acdefghjklmnpqrstuvwxyz]+$/i.test(addr)) {
          el.nodeAddress.innerHTML = `<a href="/wallet/${encodeURIComponent(addr)}" style="color: var(--text-sky); text-decoration: underline;">${addr}</a>`;
        } else {
          el.nodeAddress.textContent = state.overview.nodeAddress;
        }
      } else {
        el.nodeAddressItem.style.display = "none";
      }
    }

    if (el.knownNodesBadge) el.knownNodesBadge.textContent = state.overview.knownNodes + " TRACKED";
    if (el.knownNodesDesc) el.knownNodesDesc.textContent = `This node is connected to ${state.overview.knownNodes} verified Tor onion peers in the Sikka network.`;

    renderFeaturedPeer();

    // Render Tips
    if (el.tipsBadge) el.tipsBadge.textContent = `${state.tips.length} ACTIVE TIPS`;
    if (el.tipsFeed) {
      if (!state.tipsLoaded) {
        el.tipsFeed.innerHTML = '<div style="padding: 1rem; color: var(--text-muted); font-family: var(--font-mono); font-size: 0.875rem;">Loading DAG tips…</div>';
      } else if (!state.tips.length) {
        el.tipsFeed.innerHTML = '<div style="padding: 1rem; color: var(--text-muted); font-family: var(--font-mono); font-size: 0.875rem;">No active tips available.</div>';
      } else {
        el.tipsFeed.innerHTML = state.tips.map(txid => `
          <a href="/tx/${encodeURIComponent(txid)}" class="tip-row">
            <span class="tip-hash">${txid}</span>
            <span class="tip-badge">INSPECT &rarr;</span>
          </a>
        `).join('');
      }
    }
  }

  function pickRandomPeer() {
    if (!state.knownPeersList.length) return;
    const randomIndex = Math.floor(Math.random() * state.knownPeersList.length);
    state.featuredPeer = state.knownPeersList[randomIndex];
    renderFeaturedPeer();
  }

  function renderFeaturedPeer() {
    if (el.featuredPeerContainer && el.featuredPeerUrl) {
      if (state.featuredPeer) {
        el.featuredPeerContainer.style.display = "block";
        el.featuredPeerUrl.textContent = state.featuredPeer;
      } else {
        el.featuredPeerContainer.style.display = "none";
      }
    }
  }

  // Load Data
  async function loadNodeOverview() {
    try {
      const [, status, peersResp] = await Promise.all([
        fetchJSON("/healthz"),
        fetchJSON("/v1/status"),
        fetchJSON("/v1/discovery/nodes").catch(() => null)
      ]);

      const torHealth = String(status.network_health || "unavailable");
      const advertisedAddress = status.addresses?.[0] || status.onion_hostname || "";
      const tips = Array.isArray(status.tips) ? status.tips : [];
      const quote = await fetchNetworkPowQuote(tips).catch(() => null);

      if (peersResp && Array.isArray(peersResp.items) && peersResp.items.length > 0) {
        state.knownPeersList = peersResp.items;
        if (!state.featuredPeer) {
          pickRandomPeer();
        }
      }

      state.overview.torNetwork = formatTorNetwork(status, torHealth);
      state.overview.publicURL = advertisedAddress.replace(/^http:\/\//, "") || "Not advertised";
      state.overview.nodeAddress = String(status.node_address ?? "--");
      state.overview.nodeMessage = String(status.node_message ?? "--");
      state.overview.softwareVersion = String(status.software_version ?? "--");
      state.overview.dagSize = String(status.dag_size ?? "--");
      state.overview.tipCount = String(status.tip_count ?? "--");
      state.overview.maxDepth = String(status.max_dag_depth ?? "--");
      state.overview.knownNodes = String(status.known_node_count ?? "--");
      state.tips = tips;
      state.tipsLoaded = true;
      applySubmitPow(quote);
    } catch (error) {
      state.overview.torNetwork = "Unavailable";
      state.overview.publicURL = "Unavailable";
      state.overview.nodeAddress = "Unavailable";
      state.overview.nodeMessage = "Unavailable";
      state.overview.softwareVersion = "--";
      state.overview.dagSize = "--";
      state.overview.tipCount = "--";
      state.overview.maxDepth = "--";
      state.overview.knownNodes = "--";
      state.overview.submitPow = "--";
      state.overview.submitPowNote = "Unavailable";
      state.tips = [];
      state.tipsLoaded = true;
    }
    updateUI();
  }

  // Search Handler
  function handleSearch(e) {
    e.preventDefault();
    if (!el.searchInput) return;
    const raw = el.searchInput.value.trim();
    if (!raw) {
      setSearchFeedback("Paste a transaction ID or address first.", "error");
      return;
    }
    if (/^[A-Fa-f0-9]{64}$/.test(raw)) {
      window.location.assign("/tx/" + encodeURIComponent(raw));
      return;
    }
    if (/^sikka1[023456789acdefghjklmnpqrstuvwxyz]+$/i.test(raw)) {
      window.location.assign("/wallet/" + encodeURIComponent(raw));
      return;
    }
    setSearchFeedback("Not recognised - enter a 64-character transaction ID or a sikka1... address.", "error");
  }

  function setSearchFeedback(msg, kind) {
    if (!el.searchFeedback) return;
    el.searchFeedback.textContent = msg;
    el.searchFeedback.style.color = kind === 'error' ? 'var(--text-rose)' : 'var(--text-muted)';
    el.searchFeedback.style.display = msg ? 'block' : 'none';
  }

  // Peer Announcement Handler
  async function handlePeerSubmit(e) {
    e.preventDefault();
    if (!el.peerInput) return;
    const address = el.peerInput.value.trim();
    if (!address) {
      setPeerFeedback("Enter one onion URL to validate.", "error");
      return;
    }

    state.peerPending = true;
    if (el.peerBtn) {
      el.peerBtn.disabled = true;
      el.peerBtn.textContent = "Checking…";
    }
    setPeerFeedback("Checking peer status and compatibility...", "pending");

    try {
      const response = await fetch("/v1/discovery/announce", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ addresses: [address] }),
      });

      let payload = null;
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        payload = await response.json();
      } else {
        const text = (await response.text()).trim();
        throw new Error(text || "Peer validation failed.");
      }

      if (!response.ok) {
        throw new Error(payload.error || "Peer validation failed.");
      }

      const knownNodeCount = typeof payload.known_node_count === "number" ? payload.known_node_count : null;
      if (payload.status === "accepted") {
        const suffix = knownNodeCount === null ? "" : " Known nodes: " + knownNodeCount + ".";
        setPeerFeedback("Peer verified and added." + suffix, "success");
        el.peerInput.value = "";
        await loadNodeOverview();
        return;
      }

      setPeerFeedback("Peer was ignored because it is already known or maps back to this node.", "pending");
    } catch (error) {
      setPeerFeedback(error.message || "Peer validation failed.", "error");
    } finally {
      state.peerPending = false;
      if (el.peerBtn) {
        el.peerBtn.disabled = false;
        el.peerBtn.textContent = "Add Peer";
      }
    }
  }

  function setPeerFeedback(msg, kind) {
    if (!el.peerFeedback) return;
    el.peerFeedback.textContent = msg;
    el.peerFeedback.style.color = kind === 'error' ? 'var(--text-rose)' : 'var(--text-sky)';
    el.peerFeedback.style.display = msg ? 'block' : 'none';
  }

  // Init
  document.addEventListener('DOMContentLoaded', () => {
    if (el.searchForm) el.searchForm.addEventListener('submit', handleSearch);
    if (el.peerForm) el.peerForm.addEventListener('submit', handlePeerSubmit);
    if (el.shufflePeerBtn) el.shufflePeerBtn.addEventListener('click', pickRandomPeer);

    loadNodeOverview();
    state.pollHandle = window.setInterval(loadNodeOverview, 15000);
  });
})();
