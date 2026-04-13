// NetGuardians Content Script
// Runs on every page to detect trackers, analytics, session replay, and data collection signals

(function () {
  "use strict";

  // ── Known tracker / analytics / session-replay domains ────────────────────
  const TRACKER_DB = {
    analytics: [
      { pattern: "google-analytics.com", company: "Google", type: "Analytics", description: "Tracks page views, user sessions, and behavioral events across your visit." },
      { pattern: "googletagmanager.com", company: "Google", type: "Tag Manager", description: "Loads and manages multiple tracking scripts dynamically on the page." },
      { pattern: "analytics.google.com", company: "Google", type: "Analytics", description: "Collects detailed browsing behavior and demographic data." },
      { pattern: "plausible.io", company: "Plausible", type: "Analytics", description: "Privacy-focused analytics that tracks page views without personal data." },
      { pattern: "matomo", company: "Matomo", type: "Analytics", description: "Open-source analytics platform tracking visitor behavior." },
      { pattern: "mixpanel.com", company: "Mixpanel", type: "Analytics", description: "Tracks user interactions and behavioral events in detail." },
      { pattern: "segment.com", company: "Segment", type: "Data Pipeline", description: "Collects user data and routes it to multiple third-party analytics services." },
      { pattern: "segment.io", company: "Segment", type: "Data Pipeline", description: "Collects user data and routes it to multiple third-party analytics services." },
      { pattern: "amplitude.com", company: "Amplitude", type: "Analytics", description: "Product analytics platform tracking user behavior and engagement." },
      { pattern: "heap.io", company: "Heap", type: "Analytics", description: "Automatically captures all user interactions on the page." },
      { pattern: "heapanalytics.com", company: "Heap", type: "Analytics", description: "Automatically captures all user interactions on the page." },
      { pattern: "hotjar.com", company: "Hotjar", type: "Analytics + Session Replay", description: "Records user sessions and tracks mouse movements, clicks, and scrolling." },
      { pattern: "clarity.ms", company: "Microsoft", type: "Session Replay", description: "Records your browsing session including mouse movements, clicks, and scrolls." },
      { pattern: "fullstory.com", company: "FullStory", type: "Session Replay", description: "Records complete user sessions including all interactions and page content." },
      { pattern: "logrocket.com", company: "LogRocket", type: "Session Replay", description: "Records user sessions and captures network requests and console logs." },
      { pattern: "mouseflow.com", company: "Mouseflow", type: "Session Replay", description: "Records mouse movements, clicks, scrolls, and form interactions." },
      { pattern: "crazyegg.com", company: "Crazy Egg", type: "Heatmap/Analytics", description: "Creates heatmaps of where users click and how far they scroll." },
      { pattern: "luckyorange.com", company: "Lucky Orange", type: "Session Replay", description: "Records visitor sessions and generates heatmaps." }
    ],
    advertising: [
      { pattern: "doubleclick.net", company: "Google", type: "Ad Network", description: "Serves targeted ads and tracks your browsing across millions of websites." },
      { pattern: "googlesyndication.com", company: "Google", type: "Ad Network", description: "Delivers Google ads and collects data for ad targeting." },
      { pattern: "googleadservices.com", company: "Google", type: "Ad Conversion", description: "Tracks whether you complete actions after clicking Google ads." },
      { pattern: "facebook.net", company: "Meta", type: "Social Tracking", description: "Tracks your browsing activity to target ads on Facebook and Instagram." },
      { pattern: "facebook.com/tr", company: "Meta", type: "Pixel Tracking", description: "Meta Pixel — reports your page visits and actions back to Facebook for ad targeting." },
      { pattern: "connect.facebook", company: "Meta", type: "Social Tracking", description: "Enables Facebook integration and tracks your activity for ad targeting." },
      { pattern: "ads-twitter.com", company: "X (Twitter)", type: "Ad Tracking", description: "Tracks your browsing to serve targeted ads on X/Twitter." },
      { pattern: "t.co", company: "X (Twitter)", type: "Link Tracking", description: "Tracks clicks on links shared via X/Twitter." },
      { pattern: "amazon-adsystem.com", company: "Amazon", type: "Ad Network", description: "Serves Amazon ads and tracks browsing for product recommendations." },
      { pattern: "criteo.com", company: "Criteo", type: "Retargeting", description: "Tracks products you view to show retargeted ads across other websites." },
      { pattern: "outbrain.com", company: "Outbrain", type: "Content Ads", description: "Tracks your reading behavior to recommend sponsored content." },
      { pattern: "taboola.com", company: "Taboola", type: "Content Ads", description: "Tracks browsing to show sponsored content recommendations." },
      { pattern: "adnxs.com", company: "Xandr (Microsoft)", type: "Ad Exchange", description: "Programmatic ad exchange that tracks browsing across sites." },
      { pattern: "adsrvr.org", company: "The Trade Desk", type: "Ad Platform", description: "Programmatic advertising platform tracking users across the web." },
      { pattern: "rubiconproject.com", company: "Magnite", type: "Ad Exchange", description: "Automated ad marketplace that tracks user data for targeting." },
      { pattern: "pubmatic.com", company: "PubMatic", type: "Ad Exchange", description: "Sells ad space using your browsing data for targeting." },
      { pattern: "tiktok.com", company: "TikTok (ByteDance)", type: "Social Tracking", description: "Tracks browsing activity for ad targeting on TikTok." },
      { pattern: "snap.com", company: "Snap Inc.", type: "Social Tracking", description: "Tracks browsing for ad targeting on Snapchat." },
      { pattern: "linkedin.com/px", company: "LinkedIn (Microsoft)", type: "Professional Tracking", description: "Tracks page visits for LinkedIn ad targeting and audience building." }
    ],
    fingerprinting: [
      { pattern: "fingerprintjs", company: "FingerprintJS", type: "Browser Fingerprinting", description: "Creates a unique identifier for your browser without using cookies — very difficult to block." },
      { pattern: "fpjs.io", company: "FingerprintJS", type: "Browser Fingerprinting", description: "Advanced browser fingerprinting that can identify you even in incognito mode." }
    ]
  };

  // ── Detection functions ───────────────────────────────────────────────────

  function detectThirdPartyScripts() {
    const scripts = document.querySelectorAll("script[src]");
    const currentHost = window.location.hostname;
    const found = [];

    scripts.forEach((script) => {
      const src = script.getAttribute("src") || "";
      // Check all tracker categories
      for (const category of Object.keys(TRACKER_DB)) {
        for (const tracker of TRACKER_DB[category]) {
          if (src.includes(tracker.pattern)) {
            found.push({
              ...tracker,
              category,
              source: src,
              isThirdParty: !src.includes(currentHost)
            });
          }
        }
      }
    });

    return found;
  }

  function detectCookies() {
    const cookies = document.cookie.split(";").map((c) => c.trim()).filter(Boolean);
    const knownTrackerCookies = [
      { name: "_ga", company: "Google Analytics", description: "Identifies unique visitors across sessions." },
      { name: "_gid", company: "Google Analytics", description: "Identifies unique visitors for 24 hours." },
      { name: "_gat", company: "Google Analytics", description: "Throttles request rate to Google Analytics." },
      { name: "_fbp", company: "Meta (Facebook)", description: "Tracks visitors across websites for Facebook ad targeting." },
      { name: "_fbc", company: "Meta (Facebook)", description: "Stores Facebook click identifiers for conversion tracking." },
      { name: "fr", company: "Meta (Facebook)", description: "Facebook ad delivery and measurement cookie." },
      { name: "_gcl", company: "Google Ads", description: "Stores Google Ads click information for conversion tracking." },
      { name: "IDE", company: "Google DoubleClick", description: "Used for targeted advertising across Google's ad network." },
      { name: "NID", company: "Google", description: "Stores preferences and information for Google ads." },
      { name: "_tt_", company: "TikTok", description: "Tracks visitor activity for TikTok ad targeting." },
      { name: "li_sugr", company: "LinkedIn", description: "LinkedIn browser identifier for ad targeting." },
      { name: "_uetsid", company: "Microsoft/Bing", description: "Bing Ads universal event tracking session ID." },
      { name: "_uetvid", company: "Microsoft/Bing", description: "Bing Ads visitor tracking across sessions." }
    ];

    const detectedCookies = [];
    const totalCount = cookies.length;

    cookies.forEach((cookie) => {
      const name = cookie.split("=")[0].trim();
      const match = knownTrackerCookies.find(
        (tc) => name.startsWith(tc.name) || name === tc.name
      );
      if (match) {
        detectedCookies.push({ ...match, cookieName: name });
      }
    });

    return { total: totalCount, tracking: detectedCookies };
  }

  function detectSessionReplay() {
    const indicators = [];

    // Check for known session replay script patterns in all scripts
    const allScripts = document.querySelectorAll("script");
    const replayPatterns = [
      { pattern: "hotjar", name: "Hotjar", description: "This site records your mouse movements, clicks, scrolling, and may capture form inputs." },
      { pattern: "clarity", name: "Microsoft Clarity", description: "This site records your browsing session including mouse movements and clicks." },
      { pattern: "fullstory", name: "FullStory", description: "This site records your complete session including all interactions." },
      { pattern: "logrocket", name: "LogRocket", description: "This site records your session and captures network activity." },
      { pattern: "mouseflow", name: "Mouseflow", description: "This site records mouse movements, clicks, and form interactions." },
      { pattern: "smartlook", name: "Smartlook", description: "This site records your screen and user interactions." },
      { pattern: "luckyorange", name: "Lucky Orange", description: "This site records visitor sessions and generates interaction heatmaps." },
      { pattern: "rrweb", name: "rrweb", description: "This site uses session recording technology to replay your browsing." }
    ];

    allScripts.forEach((script) => {
      const content = (script.src || "") + " " + (script.textContent || "");
      for (const rp of replayPatterns) {
        if (content.toLowerCase().includes(rp.pattern)) {
          if (!indicators.find((i) => i.name === rp.name)) {
            indicators.push(rp);
          }
        }
      }
    });

    return indicators;
  }

  function detectStorageBehavior() {
    const results = { localStorage: 0, sessionStorage: 0, indexedDB: false };

    try {
      results.localStorage = localStorage.length;
    } catch (e) { /* blocked */ }

    try {
      results.sessionStorage = sessionStorage.length;
    } catch (e) { /* blocked */ }

    try {
      if (window.indexedDB) {
        // Just check if indexedDB is available
        results.indexedDB = true;
      }
    } catch (e) { /* blocked */ }

    return results;
  }

  function detectCanvasFingerprinting() {
    // Check for canvas fingerprinting indicators in scripts
    const scripts = document.querySelectorAll("script");
    let detected = false;
    const patterns = ["toDataURL", "getImageData", "canvas.width", "fingerprint"];

    scripts.forEach((script) => {
      const text = script.textContent || "";
      let matchCount = 0;
      patterns.forEach((p) => {
        if (text.includes(p)) matchCount++;
      });
      if (matchCount >= 2) detected = true;
    });

    return detected;
  }

  function detectThirdPartyIframes() {
    const iframes = document.querySelectorAll("iframe");
    const currentHost = window.location.hostname;
    const thirdParty = [];

    iframes.forEach((iframe) => {
      const src = iframe.getAttribute("src") || "";
      try {
        const url = new URL(src, window.location.href);
        if (url.hostname && !url.hostname.includes(currentHost)) {
          thirdParty.push({
            src: url.hostname,
            fullSrc: src,
            hidden: iframe.offsetWidth === 0 || iframe.offsetHeight === 0
              || iframe.style.display === "none" || iframe.style.visibility === "hidden"
          });
        }
      } catch (e) { /* invalid URL */ }
    });

    return thirdParty;
  }

  // ── Run all detections and send to background ─────────────────────────────

  function runAnalysis() {
    const trackers = detectThirdPartyScripts();
    const cookies = detectCookies();
    const sessionReplay = detectSessionReplay();
    const storage = detectStorageBehavior();
    const canvasFingerprinting = detectCanvasFingerprinting();
    const thirdPartyIframes = detectThirdPartyIframes();

    // Organize by category
    const analyticTrackers = trackers.filter((t) => t.category === "analytics");
    const adTrackers = trackers.filter((t) => t.category === "advertising");
    const fpTrackers = trackers.filter((t) => t.category === "fingerprinting");

    const analysisResult = {
      url: window.location.href,
      hostname: window.location.hostname,
      timestamp: Date.now(),
      trackers: {
        analytics: analyticTrackers,
        advertising: adTrackers,
        fingerprinting: fpTrackers,
        total: trackers.length
      },
      cookies: cookies,
      sessionReplay: sessionReplay,
      storage: storage,
      canvasFingerprinting: canvasFingerprinting,
      thirdPartyIframes: thirdPartyIframes,
      thirdPartyCount: new Set(trackers.map((t) => t.company)).size
    };

    // Send to background script for scoring
    chrome.runtime.sendMessage(
      { type: "ANALYSIS_RESULT", data: analysisResult },
      (response) => {
        // Background will store the scored result
      }
    );
  }

  // Run after a short delay to let the page finish loading dynamic scripts
  setTimeout(runAnalysis, 1500);
})();
