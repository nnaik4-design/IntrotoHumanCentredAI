// NetGuardians Background Service Worker
// Handles risk scoring, badge updates, credibility checks, whitelist, and demo mode

// ── Suspicious / scam domain lists (credibility layer) ──────────────────────
const KNOWN_PHISHING_PATTERNS = [
  "login-secure-", "account-verify-", "paypal-", "signin-", "update-billing",
  "confirm-identity", "secure-login", "banking-", "wallet-connect-",
  "prize-winner", "free-gift", "claim-reward", "urgent-action",
  "crypto-airdrop", "nft-mint-free", "metamask-verify"
];

const SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".club", ".work", ".click", ".loan", ".racing",
  ".download", ".stream", ".gq", ".ml", ".cf", ".tk", ".buzz",
  ".monster", ".rest", ".hair", ".skin"
];

// ── Demo mode scenarios ─────────────────────────────────────────────────────
const DEMO_SCENARIOS = {
  // Green — safe site
  "example.com": {
    riskLevel: "low",
    riskScore: 12,
    riskColor: "green",
    headline: "This site appears safe",
    rationale: "No significant trackers, advertising networks, or session replay tools were detected. The site uses minimal cookies for basic functionality only.",
    recommendation: "You can browse this site normally.",
    trackers: { analytics: [], advertising: [], fingerprinting: [], total: 0 },
    cookies: { total: 2, tracking: [] },
    sessionReplay: [],
    thirdPartyCount: 0,
    canvasFingerprinting: false,
    credibility: { score: 95, warnings: [], isEstablished: true },
    storage: { localStorage: 1, sessionStorage: 0, indexedDB: false },
    thirdPartyIframes: []
  },

  // Yellow — moderate tracking (e.g., a news/media site)
  "demo-newssite.example": {
    riskLevel: "moderate",
    riskScore: 52,
    riskColor: "yellow",
    headline: "Moderate data collection detected",
    rationale: "This site loads 8 third-party trackers from 5 different companies, including advertising networks and analytics tools. Your browsing behavior on this site is shared with multiple third parties for ad targeting.",
    recommendation: "Consider using an ad blocker. Avoid entering sensitive personal information on this site.",
    trackers: {
      analytics: [
        { company: "Google", type: "Analytics", description: "Tracks page views, user sessions, and behavioral events across your visit.", category: "analytics" },
        { company: "Google", type: "Tag Manager", description: "Loads and manages multiple tracking scripts dynamically on the page.", category: "analytics" },
        { company: "Mixpanel", type: "Analytics", description: "Tracks user interactions and behavioral events in detail.", category: "analytics" }
      ],
      advertising: [
        { company: "Google", type: "Ad Network", description: "Serves targeted ads and tracks your browsing across millions of websites.", category: "advertising" },
        { company: "Meta", type: "Pixel Tracking", description: "Meta Pixel — reports your page visits and actions back to Facebook for ad targeting.", category: "advertising" },
        { company: "Criteo", type: "Retargeting", description: "Tracks products you view to show retargeted ads across other websites.", category: "advertising" },
        { company: "Taboola", type: "Content Ads", description: "Tracks browsing to show sponsored content recommendations.", category: "advertising" },
        { company: "Outbrain", type: "Content Ads", description: "Tracks your reading behavior to recommend sponsored content.", category: "advertising" }
      ],
      fingerprinting: [],
      total: 8
    },
    cookies: {
      total: 18,
      tracking: [
        { company: "Google Analytics", description: "Identifies unique visitors across sessions.", cookieName: "_ga" },
        { company: "Google Analytics", description: "Identifies unique visitors for 24 hours.", cookieName: "_gid" },
        { company: "Meta (Facebook)", description: "Tracks visitors across websites for Facebook ad targeting.", cookieName: "_fbp" },
        { company: "Google Ads", description: "Stores Google Ads click information for conversion tracking.", cookieName: "_gcl_au" }
      ]
    },
    sessionReplay: [],
    thirdPartyCount: 5,
    canvasFingerprinting: false,
    credibility: { score: 72, warnings: ["High volume of advertising trackers detected"], isEstablished: true },
    storage: { localStorage: 8, sessionStorage: 3, indexedDB: true },
    thirdPartyIframes: [
      { src: "doubleclick.net", hidden: false },
      { src: "facebook.com", hidden: true }
    ]
  },

  // Red — high risk / phishing site
  "secure-banking-login.example": {
    riskLevel: "high",
    riskScore: 89,
    riskColor: "red",
    headline: "Phishing Risk Detected!",
    rationale: "This site has multiple high-risk indicators: the domain mimics a banking login page, browser fingerprinting is active, session replay is recording all your interactions, and your data is being sent to 7 different third-party companies. This site may be attempting to steal your credentials.",
    recommendation: "Avoid entering passwords or payment information! Consider leaving this site immediately.",
    trackers: {
      analytics: [
        { company: "Google", type: "Analytics", description: "Tracks page views, user sessions, and behavioral events across your visit.", category: "analytics" },
        { company: "Heap", type: "Analytics", description: "Automatically captures all user interactions on the page.", category: "analytics" }
      ],
      advertising: [
        { company: "Google", type: "Ad Network", description: "Serves targeted ads and tracks your browsing across millions of websites.", category: "advertising" },
        { company: "Meta", type: "Pixel Tracking", description: "Meta Pixel — reports your page visits and actions back to Facebook for ad targeting.", category: "advertising" },
        { company: "The Trade Desk", type: "Ad Platform", description: "Programmatic advertising platform tracking users across the web.", category: "advertising" },
        { company: "Xandr (Microsoft)", type: "Ad Exchange", description: "Programmatic ad exchange that tracks browsing across sites.", category: "advertising" }
      ],
      fingerprinting: [
        { company: "FingerprintJS", type: "Browser Fingerprinting", description: "Creates a unique identifier for your browser without using cookies — very difficult to block.", category: "fingerprinting" }
      ],
      total: 7
    },
    cookies: {
      total: 24,
      tracking: [
        { company: "Google Analytics", description: "Identifies unique visitors across sessions.", cookieName: "_ga" },
        { company: "Meta (Facebook)", description: "Tracks visitors across websites for Facebook ad targeting.", cookieName: "_fbp" },
        { company: "Google DoubleClick", description: "Used for targeted advertising across Google's ad network.", cookieName: "IDE" },
        { company: "TikTok", description: "Tracks visitor activity for TikTok ad targeting.", cookieName: "_tt_enable_cookie" }
      ]
    },
    sessionReplay: [
      { name: "FullStory", description: "This site records your complete session including all interactions." },
      { name: "Mouseflow", description: "This site records mouse movements, clicks, and form interactions." }
    ],
    thirdPartyCount: 7,
    canvasFingerprinting: true,
    credibility: {
      score: 15,
      warnings: [
        "Domain name mimics a banking login page — possible phishing",
        "Browser fingerprinting actively identifying your device",
        "Session replay recording all your interactions",
        "Unusually high number of tracking scripts for this type of site"
      ],
      isEstablished: false
    },
    storage: { localStorage: 14, sessionStorage: 6, indexedDB: true },
    thirdPartyIframes: [
      { src: "doubleclick.net", hidden: true },
      { src: "facebook.com", hidden: true },
      { src: "unknown-tracker.xyz", hidden: true }
    ]
  }
};

// ── Risk scoring engine ─────────────────────────────────────────────────────

function computeRiskScore(data) {
  let score = 0;
  const warnings = [];

  // Tracker count scoring
  const trackerTotal = data.trackers.total;
  if (trackerTotal >= 10) { score += 25; warnings.push("Very high number of trackers detected"); }
  else if (trackerTotal >= 5) { score += 15; warnings.push("Multiple trackers detected"); }
  else if (trackerTotal >= 2) { score += 8; }

  // Advertising tracker penalty
  const adCount = data.trackers.advertising.length;
  if (adCount >= 5) { score += 20; warnings.push("Extensive advertising network presence"); }
  else if (adCount >= 2) { score += 10; }

  // Session replay is a major concern
  if (data.sessionReplay.length > 0) {
    score += 20;
    warnings.push("Session replay is recording your interactions");
  }

  // Fingerprinting
  if (data.trackers.fingerprinting.length > 0 || data.canvasFingerprinting) {
    score += 20;
    warnings.push("Browser fingerprinting detected — you can be tracked without cookies");
  }

  // Tracking cookies
  if (data.cookies.tracking.length >= 4) { score += 10; }
  else if (data.cookies.tracking.length >= 2) { score += 5; }

  // Third-party iframes (especially hidden ones)
  const hiddenIframes = (data.thirdPartyIframes || []).filter((f) => f.hidden);
  if (hiddenIframes.length >= 2) {
    score += 10;
    warnings.push("Hidden third-party content detected on this page");
  }

  // Credibility checks
  const hostname = data.hostname || "";
  const credResult = checkCredibility(hostname);

  if (!credResult.isEstablished) { score += 15; }
  score += credResult.warnings.length * 10;
  warnings.push(...credResult.warnings);

  // Cap at 100
  score = Math.min(score, 100);

  // Determine level
  let riskLevel, riskColor, headline, recommendation;

  if (score <= 25) {
    riskLevel = "low";
    riskColor = "green";
    headline = "This site appears safe";
    recommendation = "You can browse this site normally.";
  } else if (score <= 55) {
    riskLevel = "moderate";
    riskColor = "yellow";
    headline = "Moderate data collection detected";
    recommendation = "Be cautious with personal information. Consider reviewing what data this site collects.";
  } else {
    riskLevel = "high";
    riskColor = "red";
    headline = "High privacy risk detected";
    recommendation = "Avoid entering sensitive information. Consider leaving this site.";
  }

  // Generate rationale
  const rationale = generateRationale(data, warnings);

  return {
    ...data,
    riskScore: score,
    riskLevel,
    riskColor,
    headline,
    rationale,
    recommendation,
    credibility: credResult
  };
}

function checkCredibility(hostname) {
  const result = { score: 70, warnings: [], isEstablished: true };

  // Check for phishing patterns in hostname
  for (const pattern of KNOWN_PHISHING_PATTERNS) {
    if (hostname.includes(pattern)) {
      result.warnings.push(`Domain name contains suspicious pattern "${pattern}" — possible phishing`);
      result.isEstablished = false;
      result.score -= 30;
    }
  }

  // Check for suspicious TLDs
  for (const tld of SUSPICIOUS_TLDS) {
    if (hostname.endsWith(tld)) {
      result.warnings.push(`Uses uncommon domain extension (${tld}) often associated with spam`);
      result.score -= 15;
    }
  }

  // Check for IP address as hostname
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    result.warnings.push("Site uses an IP address instead of a domain name — unusual for legitimate sites");
    result.isEstablished = false;
    result.score -= 20;
  }

  // Check for very long hostname (often used in phishing)
  if (hostname.length > 40) {
    result.warnings.push("Unusually long domain name — sometimes used to disguise phishing URLs");
    result.score -= 10;
  }

  // Check for excessive subdomains
  const parts = hostname.split(".");
  if (parts.length > 4) {
    result.warnings.push("Excessive subdomains detected — can be a sign of domain manipulation");
    result.score -= 10;
  }

  result.score = Math.max(result.score, 0);
  return result;
}

function generateRationale(data, warnings) {
  const parts = [];
  const trackerTotal = data.trackers.total;
  const companies = data.thirdPartyCount;

  if (trackerTotal === 0 && data.sessionReplay.length === 0) {
    return "No significant trackers or session replay tools were detected on this site. Cookie usage appears minimal and limited to basic site functionality.";
  }

  if (trackerTotal > 0) {
    parts.push(`This site loads ${trackerTotal} third-party tracker${trackerTotal > 1 ? "s" : ""} from ${companies} different compan${companies > 1 ? "ies" : "y"}.`);
  }

  if (data.trackers.advertising.length > 0) {
    const adCompanies = [...new Set(data.trackers.advertising.map((t) => t.company))];
    parts.push(`Your browsing behavior is shared with advertising networks including ${adCompanies.slice(0, 3).join(", ")}${adCompanies.length > 3 ? " and others" : ""}.`);
  }

  if (data.sessionReplay.length > 0) {
    const replayNames = data.sessionReplay.map((r) => r.name).join(" and ");
    parts.push(`${replayNames} ${data.sessionReplay.length > 1 ? "are" : "is"} actively recording your session — including mouse movements, clicks, and scrolling.`);
  }

  if (data.canvasFingerprinting || data.trackers.fingerprinting.length > 0) {
    parts.push("Browser fingerprinting is being used to create a unique identifier for your device, which can track you even without cookies.");
  }

  if (data.cookies.tracking.length > 0) {
    parts.push(`${data.cookies.tracking.length} tracking cookie${data.cookies.tracking.length > 1 ? "s" : ""} ${data.cookies.tracking.length > 1 ? "are" : "is"} being used to identify you across browsing sessions.`);
  }

  return parts.join(" ");
}

// ── Badge and icon management ───────────────────────────────────────────────

function updateBadge(tabId, riskColor, riskLevel) {
  const badgeColors = {
    green: "#22c55e",
    yellow: "#eab308",
    red: "#ef4444"
  };

  const badgeText = {
    green: "",
    yellow: "!",
    red: "!!"
  };

  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: badgeColors[riskColor] || "#6b7280"
  });

  chrome.action.setBadgeText({
    tabId,
    text: badgeText[riskColor] || ""
  });

  chrome.action.setTitle({
    tabId,
    title: `NetGuardians — Risk: ${riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1)}`
  });
}

// ── Message handling ────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYSIS_RESULT" && sender.tab) {
    const tabId = sender.tab.id;
    const hostname = message.data.hostname;

    // Check whitelist first
    chrome.storage.local.get(["whitelist", "demoMode"], (stored) => {
      const whitelist = stored.whitelist || [];
      const demoMode = stored.demoMode !== false; // default to true

      // Check demo mode
      if (demoMode && DEMO_SCENARIOS[hostname]) {
        const demoResult = DEMO_SCENARIOS[hostname];
        chrome.storage.local.set({ [`analysis_${tabId}`]: demoResult });
        updateBadge(tabId, demoResult.riskColor, demoResult.riskLevel);
        sendResponse({ status: "demo" });
        return;
      }

      // Check whitelist
      if (whitelist.includes(hostname)) {
        const safeResult = {
          ...message.data,
          riskScore: 0,
          riskLevel: "whitelisted",
          riskColor: "green",
          headline: "Trusted Site (Whitelisted)",
          rationale: "You've marked this site as trusted. NetGuardians will not analyze it.",
          recommendation: "No action needed — this site is on your trusted list.",
          credibility: { score: 100, warnings: [], isEstablished: true },
          isWhitelisted: true
        };
        chrome.storage.local.set({ [`analysis_${tabId}`]: safeResult });
        updateBadge(tabId, "green", "whitelisted");
        sendResponse({ status: "whitelisted" });
        return;
      }

      // Normal analysis
      const scored = computeRiskScore(message.data);
      chrome.storage.local.set({ [`analysis_${tabId}`]: scored });
      updateBadge(tabId, scored.riskColor, scored.riskLevel);
      sendResponse({ status: "scored" });
    });

    return true; // async response
  }

  if (message.type === "GET_ANALYSIS") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs[0]) { sendResponse(null); return; }
      const tabId = tabs[0].id;
      const hostname = new URL(tabs[0].url || "about:blank").hostname;

      chrome.storage.local.get(["demoMode", `analysis_${tabId}`], (stored) => {
        const demoMode = stored.demoMode !== false;

        // Check demo scenarios for the current hostname
        if (demoMode && DEMO_SCENARIOS[hostname]) {
          sendResponse(DEMO_SCENARIOS[hostname]);
          return;
        }

        sendResponse(stored[`analysis_${tabId}`] || null);
      });
    });
    return true;
  }

  if (message.type === "ADD_TO_WHITELIST") {
    chrome.storage.local.get(["whitelist"], (stored) => {
      const whitelist = stored.whitelist || [];
      if (!whitelist.includes(message.hostname)) {
        whitelist.push(message.hostname);
        chrome.storage.local.set({ whitelist });
      }
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === "REMOVE_FROM_WHITELIST") {
    chrome.storage.local.get(["whitelist"], (stored) => {
      let whitelist = stored.whitelist || [];
      whitelist = whitelist.filter((h) => h !== message.hostname);
      chrome.storage.local.set({ whitelist });
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === "GET_WHITELIST") {
    chrome.storage.local.get(["whitelist"], (stored) => {
      sendResponse(stored.whitelist || []);
    });
    return true;
  }

  if (message.type === "SET_DEMO_MODE") {
    chrome.storage.local.set({ demoMode: message.enabled });
    sendResponse({ success: true });
    return true;
  }

  if (message.type === "GET_DEMO_MODE") {
    chrome.storage.local.get(["demoMode"], (stored) => {
      sendResponse(stored.demoMode !== false);
    });
    return true;
  }
});

// Initialize default settings
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    whitelist: [],
    demoMode: true
  });
});
