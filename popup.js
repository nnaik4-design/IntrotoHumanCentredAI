// NetGuardians Popup Script
// Handles all UI interactions, tab switching, and data rendering

document.addEventListener("DOMContentLoaded", () => {
  // ── Tab navigation ──────────────────────────────────────────────────────
  const tabs = document.querySelectorAll(".tab");
  const tabContents = document.querySelectorAll(".tab-content");

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      tabContents.forEach((tc) => tc.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(`tab-${tab.dataset.tab}`).classList.add("active");
    });
  });

  // Settings button toggles to whitelist tab
  document.getElementById("settingsBtn").addEventListener("click", () => {
    tabs.forEach((t) => t.classList.remove("active"));
    tabContents.forEach((tc) => tc.classList.remove("active"));
    document.querySelector('[data-tab="whitelist"]').classList.add("active");
    document.getElementById("tab-whitelist").classList.add("active");
  });

  // ── Load analysis data ──────────────────────────────────────────────────
  let currentHostname = "";

  chrome.tabs.query({ active: true, currentWindow: true }, (activeTabs) => {
    if (!activeTabs[0] || !activeTabs[0].url || activeTabs[0].url.startsWith("chrome://")) {
      showNoData();
      return;
    }

    try {
      currentHostname = new URL(activeTabs[0].url).hostname;
    } catch (e) {
      showNoData();
      return;
    }

    document.getElementById("siteHostname").textContent = currentHostname;
    document.getElementById("whitelistCurrentSite").textContent = currentHostname;

    chrome.runtime.sendMessage({ type: "GET_ANALYSIS" }, (data) => {
      if (data) {
        renderAnalysis(data);
      } else {
        // No analysis yet — might still be loading
        setTimeout(() => {
          chrome.runtime.sendMessage({ type: "GET_ANALYSIS" }, (retryData) => {
            if (retryData) {
              renderAnalysis(retryData);
            } else {
              showNoData();
            }
          });
        }, 2000);
      }
    });
  });

  // ── Render functions ────────────────────────────────────────────────────

  function renderAnalysis(data) {
    document.getElementById("loadingState").style.display = "none";
    document.getElementById("mainContent").style.display = "block";

    renderSummary(data);
    renderTrackers(data);
    renderCredibility(data);
    loadWhitelist();
    loadDemoMode();
  }

  function renderSummary(data) {
    const banner = document.getElementById("riskBanner");
    const icon = document.getElementById("riskIcon");
    const levelLabel = document.getElementById("riskLevelLabel");
    const scoreFill = document.getElementById("riskScoreFill");
    const scoreText = document.getElementById("riskScoreText");
    const headlineCard = document.getElementById("headlineCard");
    const headline = document.getElementById("riskHeadline");
    const rationale = document.getElementById("rationaleText");
    const recommendation = document.getElementById("recommendationText");
    const recCard = document.getElementById("recommendationCard");

    // Risk banner styling
    banner.className = `risk-banner risk-${data.riskColor}`;
    headlineCard.className = `card headline-card headline-${data.riskColor}`;
    recCard.className = `card recommendation-card rec-${data.riskColor}`;

    // Icon
    if (data.riskColor === "green") {
      icon.innerHTML = '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
    } else if (data.riskColor === "yellow") {
      icon.innerHTML = '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
    } else {
      icon.innerHTML = '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
    }

    // Labels
    const levelMap = { low: "Low Risk", moderate: "Moderate Risk", high: "High Risk", whitelisted: "Trusted Site" };
    levelLabel.textContent = levelMap[data.riskLevel] || data.riskLevel;

    // Score bar
    const score = data.riskScore || 0;
    scoreFill.style.width = `${score}%`;
    scoreFill.className = `risk-score-fill fill-${data.riskColor}`;
    scoreText.textContent = `Risk score: ${score}/100`;

    // Content
    headline.textContent = data.headline;
    rationale.textContent = data.rationale;
    recommendation.textContent = data.recommendation;

    // Stats
    document.getElementById("statTrackers").textContent = data.trackers ? data.trackers.total : 0;
    document.getElementById("statCompanies").textContent = data.thirdPartyCount || 0;
    document.getElementById("statCookies").textContent = data.cookies ? data.cookies.total : 0;

    const replayCount = data.sessionReplay ? data.sessionReplay.length : 0;
    const replayStat = document.getElementById("statReplay");
    replayStat.textContent = replayCount > 0 ? "Active" : "None";
    if (replayCount > 0) replayStat.classList.add("stat-danger");
  }

  function renderTrackers(data) {
    const trackers = data.trackers || { analytics: [], advertising: [], fingerprinting: [], total: 0 };
    const sessionReplay = data.sessionReplay || [];
    const cookies = data.cookies || { total: 0, tracking: [] };

    let hasAny = false;

    // Analytics
    hasAny = renderTrackerCategory("analytics", trackers.analytics, "analyticsSection", "analyticsList", "analyticsCount") || hasAny;
    // Advertising
    hasAny = renderTrackerCategory("advertising", trackers.advertising, "advertisingSection", "advertisingList", "advertisingCount") || hasAny;
    // Fingerprinting
    hasAny = renderTrackerCategory("fingerprinting", trackers.fingerprinting, "fingerprintingSection", "fingerprintingList", "fingerprintingCount") || hasAny;

    // Session Replay
    const replaySection = document.getElementById("replaySection");
    const replayList = document.getElementById("replayList");
    const replayCountEl = document.getElementById("replayCount");
    if (sessionReplay.length > 0) {
      hasAny = true;
      replaySection.style.display = "block";
      replayCountEl.textContent = sessionReplay.length;
      replayList.innerHTML = sessionReplay.map((r) => `
        <div class="tracker-item">
          <div class="tracker-name">${escapeHtml(r.name)}</div>
          <div class="tracker-desc">${escapeHtml(r.description)}</div>
        </div>
      `).join("");
    } else {
      replaySection.style.display = "none";
    }

    // Cookies
    const cookiesSection = document.getElementById("cookiesSection");
    const cookiesList = document.getElementById("cookiesList");
    const cookiesCountEl = document.getElementById("cookiesCount");
    if (cookies.tracking && cookies.tracking.length > 0) {
      hasAny = true;
      cookiesSection.style.display = "block";
      cookiesCountEl.textContent = cookies.tracking.length;
      cookiesList.innerHTML = cookies.tracking.map((c) => `
        <div class="tracker-item">
          <div class="tracker-name">${escapeHtml(c.company)} <code>${escapeHtml(c.cookieName)}</code></div>
          <div class="tracker-desc">${escapeHtml(c.description)}</div>
        </div>
      `).join("");
    } else {
      cookiesSection.style.display = "none";
    }

    // No trackers message
    document.getElementById("noTrackersMsg").style.display = hasAny ? "none" : "flex";
  }

  function renderTrackerCategory(category, items, sectionId, listId, countId) {
    const section = document.getElementById(sectionId);
    const list = document.getElementById(listId);
    const count = document.getElementById(countId);

    if (items && items.length > 0) {
      section.style.display = "block";
      count.textContent = items.length;
      list.innerHTML = items.map((t) => `
        <div class="tracker-item">
          <div class="tracker-name">${escapeHtml(t.company)} <span class="tracker-type">${escapeHtml(t.type)}</span></div>
          <div class="tracker-desc">${escapeHtml(t.description)}</div>
        </div>
      `).join("");
      return true;
    } else {
      section.style.display = "none";
      return false;
    }
  }

  function renderCredibility(data) {
    const cred = data.credibility || { score: 70, warnings: [], isEstablished: true };
    const gaugeFill = document.getElementById("credGaugeFill");
    const label = document.getElementById("credLabel");
    const warningsList = document.getElementById("credWarningsList");
    const noWarnings = document.getElementById("noWarningsMsg");
    const scoreContainer = document.getElementById("credScoreContainer");

    // Gauge
    const score = Math.max(0, Math.min(100, cred.score));
    gaugeFill.style.width = `${score}%`;

    if (score >= 70) {
      gaugeFill.className = "credibility-gauge-fill cred-good";
      label.textContent = `Credibility: Good (${score}/100)`;
      label.className = "credibility-label cred-text-good";
    } else if (score >= 40) {
      gaugeFill.className = "credibility-gauge-fill cred-moderate";
      label.textContent = `Credibility: Moderate (${score}/100)`;
      label.className = "credibility-label cred-text-moderate";
    } else {
      gaugeFill.className = "credibility-gauge-fill cred-poor";
      label.textContent = `Credibility: Poor (${score}/100)`;
      label.className = "credibility-label cred-text-poor";
    }

    // Warnings
    if (cred.warnings && cred.warnings.length > 0) {
      noWarnings.style.display = "none";
      warningsList.style.display = "block";
      warningsList.innerHTML = cred.warnings.map((w) => `
        <div class="warning-item">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <span>${escapeHtml(w)}</span>
        </div>
      `).join("");
    } else {
      warningsList.style.display = "none";
      noWarnings.style.display = "flex";
    }
  }

  // ── Whitelist management ────────────────────────────────────────────────

  function loadWhitelist() {
    chrome.runtime.sendMessage({ type: "GET_WHITELIST" }, (whitelist) => {
      renderWhitelist(whitelist || []);
    });
  }

  function renderWhitelist(whitelist) {
    const container = document.getElementById("whitelistItems");
    const empty = document.getElementById("whitelistEmpty");
    const addBtn = document.getElementById("addWhitelistBtn");

    // Check if current site is whitelisted
    const isWhitelisted = whitelist.includes(currentHostname);
    addBtn.textContent = isWhitelisted ? "Remove current site from whitelist" : "Add current site to whitelist";
    addBtn.className = isWhitelisted ? "btn btn-secondary" : "btn btn-primary";

    if (whitelist.length === 0) {
      empty.style.display = "block";
      container.querySelectorAll(".whitelist-entry").forEach((e) => e.remove());
      return;
    }

    empty.style.display = "none";
    // Remove old entries
    container.querySelectorAll(".whitelist-entry").forEach((e) => e.remove());

    whitelist.forEach((hostname) => {
      const entry = document.createElement("div");
      entry.className = "whitelist-entry";
      entry.innerHTML = `
        <div class="whitelist-domain">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2"><path d="M12 2L3 7v6c0 5.25 3.83 10.15 9 11.25C17.17 23.15 21 18.25 21 13V7l-9-5z"/></svg>
          <span>${escapeHtml(hostname)}</span>
        </div>
        <button class="btn-remove" data-hostname="${escapeHtml(hostname)}" title="Remove">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      `;
      container.appendChild(entry);
    });

    // Attach remove handlers
    container.querySelectorAll(".btn-remove").forEach((btn) => {
      btn.addEventListener("click", () => {
        const hostname = btn.dataset.hostname;
        chrome.runtime.sendMessage({ type: "REMOVE_FROM_WHITELIST", hostname }, () => {
          loadWhitelist();
        });
      });
    });
  }

  document.getElementById("addWhitelistBtn").addEventListener("click", () => {
    if (!currentHostname) return;

    chrome.runtime.sendMessage({ type: "GET_WHITELIST" }, (whitelist) => {
      if ((whitelist || []).includes(currentHostname)) {
        chrome.runtime.sendMessage({ type: "REMOVE_FROM_WHITELIST", hostname: currentHostname }, () => {
          loadWhitelist();
        });
      } else {
        chrome.runtime.sendMessage({ type: "ADD_TO_WHITELIST", hostname: currentHostname }, () => {
          loadWhitelist();
        });
      }
    });
  });

  // ── Demo mode toggle ────────────────────────────────────────────────────

  function loadDemoMode() {
    chrome.runtime.sendMessage({ type: "GET_DEMO_MODE" }, (enabled) => {
      document.getElementById("demoModeToggle").checked = enabled;
    });
  }

  document.getElementById("demoModeToggle").addEventListener("change", (e) => {
    chrome.runtime.sendMessage({ type: "SET_DEMO_MODE", enabled: e.target.checked });
  });

  // ── Utility ─────────────────────────────────────────────────────────────

  function showNoData() {
    document.getElementById("loadingState").style.display = "none";
    document.getElementById("noDataState").style.display = "flex";
  }

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text || "";
    return div.innerHTML;
  }
});
