/* peephole fingerprint collector — passive, silent on error. */
(function () {
  "use strict";
  var TOKEN = window.PEEPHOLE_TOKEN || "";
  var behavior = { mouse_events: 0, mouse_dist: 0, clicks: 0, scrolls: 0,
                   keys: [], fill_seconds: null, events: [] };
  var lastX = null, lastY = null, firstFocus = null, submitTime = null;

  function on(ev, fn) { try { window.addEventListener(ev, fn, { passive: true }); } catch (e) {} }
  on("mousemove", function (e) {
    behavior.mouse_events++;
    if (lastX !== null) behavior.mouse_dist += Math.hypot(e.clientX - lastX, e.clientY - lastY);
    lastX = e.clientX; lastY = e.clientY;
  });
  on("click", function () { behavior.clicks++; });
  on("scroll", function () { behavior.scrolls++; });
  on("focusin", function (e) {
    if (firstFocus === null && e.target && (e.target.type === "text" || e.target.type === "password"))
      firstFocus = performance.now();
  });
  on("keydown", function (e) {
    if (behavior.keys.length < 200) behavior.keys.push({ t: performance.now(), k: e.key.length });
  });
  on("submit", function () { submitTime = performance.now();
    if (firstFocus !== null) behavior.fill_seconds = (submitTime - firstFocus) / 1000; });

  function canvasFp() {
    try {
      var c = document.createElement("canvas"); c.width = 200; c.height = 50;
      var x = c.getContext("2d");
      x.textBaseline = "top"; x.font = "14px 'Arial'"; x.fillStyle = "#f60";
      x.fillRect(10, 10, 80, 20); x.fillStyle = "#069";
      x.fillText("peephole \u{1F441} fp", 2, 15);
      return c.toDataURL().slice(-64);
    } catch (e) { return ""; }
  }
  function webglInfo() {
    try {
      var c = document.createElement("canvas");
      var g = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!g) return { vendor: "", renderer: "" };
      var d = g.getExtension("WEBGL_debug_renderer_info");
      return {
        vendor: d ? g.getParameter(d.UNMASKED_VENDOR_WEBGL) : "",
        renderer: d ? g.getParameter(d.UNMASKED_RENDERER_WEBGL) : "",
        params: [g.getParameter(g.MAX_TEXTURE_SIZE), g.getParameter(g.MAX_VIEWPORT_DIMS)].join(",")
      };
    } catch (e) { return { vendor: "", renderer: "" }; }
  }
  function fontsCount() {
    var base = ["monospace", "sans-serif", "serif"];
    var test = ["Arial", "Courier New", "Georgia", "Times New Roman", "Verdana",
                "Comic Sans MS", "Impact", "Trebuchet MS", "Helvetica", "Consolas",
                "DejaVu Sans", "Liberation Sans", "Ubuntu", "Cantarell", "Noto Sans"];
    var found = 0;
    try {
      var s = document.createElement("span");
      s.style.cssText = "position:absolute;left:-9999px;font-size:72px";
      s.textContent = "mmmmmmmmmmlli";
      document.body.appendChild(s);
      var widths = {};
      for (var b = 0; b < base.length; b++) {
        s.style.fontFamily = base[b];
        widths[base[b]] = s.offsetWidth;
      }
      for (var i = 0; i < test.length; i++) {
        for (var j = 0; j < base.length; j++) {
          s.style.fontFamily = "'" + test[i] + "'," + base[j];
          if (s.offsetWidth !== widths[base[j]]) { found++; break; }
        }
      }
      document.body.removeChild(s);
    } catch (e) {}
    return found;
  }
  function audioFp(cb) {
    try {
      var Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!Ctx) return cb("");
      var ctx = new Ctx(1, 44100, 44100);
      var osc = ctx.createOscillator(); osc.type = "triangle"; osc.frequency.value = 10000;
      var comp = ctx.createDynamicsCompressor();
      osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
      ctx.startRendering().then(function (buf) {
        var d = buf.getChannelData(0), sum = 0;
        for (var i = 4500; i < 5000; i++) sum += Math.abs(d[i]);
        cb(sum.toString().slice(0, 16));
      }).catch(function () { cb(""); });
    } catch (e) { cb(""); }
  }
  function storageProbe() {
    var r = { local: false, session: false, cookie: navigator.cookieEnabled };
    try { localStorage.setItem("pp_t", "1"); r.local = true; } catch (e) {}
    try { sessionStorage.setItem("pp_t", "1"); r.session = true; } catch (e) {}
    return r;
  }
  function visitorId() {
    try {
      var id = localStorage.getItem("pp_vid");
      if (!id) {
        id = "xxxxxxxx-xxxx".replace(/x/g, function () {
          return ((Math.random() * 16) | 0).toString(16);
        }) + "-" + Date.now().toString(16);
        localStorage.setItem("pp_vid", id);
      }
      return id;
    } catch (e) { return ""; }
  }
  function automationTells() {
    return {
      webdriver: !!navigator.webdriver,
      phantom: !!(window.callPhantom || window._phantom),
      nightmare: !!window.__nightmare,
      selenium: !!(window.__selenium_unwrapped || document.$cdc_asdjflasutopfhvcZLmcfl_),
      chrome_shape: typeof window.chrome
    };
  }

  function collect() {
    var gl = webglInfo();
    audioFp(function (audio) {
      var attrs = {
        ua: navigator.userAgent,
        platform: navigator.platform,
        languages: navigator.languages || [navigator.language],
        timezone: (function () { try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { return ""; } })(),
        screen: [screen.width, screen.height, screen.colorDepth].join("x"),
        window_delta: (screen.width - window.innerWidth) + "x" + (screen.height - window.innerHeight),
        pixel_ratio: window.devicePixelRatio || 1,
        hardware_concurrency: navigator.hardwareConcurrency || 0,
        device_memory: navigator.deviceMemory || 0,
        touch_points: navigator.maxTouchPoints || 0,
        plugins_count: navigator.plugins ? navigator.plugins.length : 0,
        canvas: canvasFp(),
        webgl_vendor: gl.vendor, webgl_renderer: gl.renderer, webgl_params: gl.params || "",
        fonts_count: fontsCount(),
        audio: audio,
        storage: storageProbe(),
        visitor_id: visitorId(),
        webdriver: !!navigator.webdriver,
        automation: automationTells(),
        dnt: navigator.doNotTrack || "",
        math_tan: Math.tan(-1e300),
        error_stack: (function () { try { null.x(); } catch (e) { return (e.stack || "").split("\n").length; } })()
      };
      delete behavior.events; // compact: summary only on first post
      var payload = JSON.stringify({ token: TOKEN, attrs: attrs, behavior: behavior });
      var sent = false;
      try { sent = navigator.sendBeacon("/collect",
        new Blob([payload], { type: "application/json" })); } catch (e) {}
      if (!sent) {
        try { fetch("/collect", { method: "POST", headers: { "content-type": "application/json" },
          body: payload, keepalive: true }); } catch (e) {}
      }
      // Panel refresh (human display) — after a short behavior window.
      setTimeout(refreshPanel, 4000);
    });
  }

  // 202 = fingerprint not stored yet (beacon still in flight): show the
  // interim status and poll again with backoff, up to ~1 minute in total.
  var panelTries = 0;
  function refreshPanel() {
    try {
      fetch("/panel?token=" + encodeURIComponent(TOKEN))
        .then(function (r) {
          if (r.status === 202 && ++panelTries < 8) setTimeout(refreshPanel, 1500 * panelTries);
          return r.ok ? r.text() : "";
        })
        .then(function (html) {
          if (!html) return;
          var host = document.getElementById("fingerprint-panel");
          if (host) {
            host.className = "card";
            // Values arrive split across <i> nodes (bot-unfriendly); they
            // concatenate naturally for human reading. Decoy <b> nodes are
            // display:none and never rendered.
            host.innerHTML = html;
          }
        }).catch(function () {});
    } catch (e) {}
  }

  if (document.readyState === "complete" || document.readyState === "interactive") collect();
  else document.addEventListener("DOMContentLoaded", collect);
})();
