(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  function el(tag, attrs, parent) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function text(parent, x, y, s, cls, anchor) {
    var t = el("text", { x: x, y: y, "class": cls || "", "text-anchor": anchor || "start" }, parent);
    t.textContent = s;
    return t;
  }
  function svg(host, w, h) {
    host.innerHTML = "";
    // width/height attributes give the element an intrinsic aspect ratio, so
    // CSS `width:100%; height:auto` scales it instead of falling back to 150px.
    return el("svg", { viewBox: "0 0 " + w + " " + h, width: w, height: h, preserveAspectRatio: "xMidYMid meet" }, host);
  }
  function empty(host, w, h) { var s = svg(host, w, h); text(s, w / 2, h / 2, "no data in this range", "empty-note", "middle"); }
  var tip = document.createElement("div"); tip.className = "tooltip"; document.body.appendChild(tip);
  function showTip(ev, html) { tip.innerHTML = html; tip.style.display = "block"; tip.style.left = (ev.clientX + 12) + "px"; tip.style.top = (ev.clientY + 12) + "px"; }
  function hideTip() { tip.style.display = "none"; }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  // Zero-fill the timeline so a quiet range still shows its full axis.
  function pad2(n) { return (n < 10 ? "0" : "") + n; }
  function bucketKey(d, hourly) {
    var k = d.getUTCFullYear() + "-" + pad2(d.getUTCMonth() + 1) + "-" + pad2(d.getUTCDate());
    return hourly ? k + "T" + pad2(d.getUTCHours()) + ":00" : k;
  }
  function fillBuckets(buckets, range) {
    var spec = { "24h": [24, true], "7d": [168, true], "30d": [30, false] }[range];
    if (!spec) return buckets;
    var byKey = {};
    buckets.forEach(function (b) { byKey[b.ts] = b.count; });
    var out = [], now = new Date(), stepMs = spec[1] ? 3600e3 : 86400e3;
    // A rolling window touches n+1 calendar buckets (the oldest is partial).
    for (var i = spec[0]; i >= 0; i--) {
      var k = bucketKey(new Date(now.getTime() - i * stepMs), spec[1]);
      out.push({ ts: k, count: byKey[k] || 0 });
    }
    return out;
  }

  // Vertical bars over time: [{ts, count}]. Single series, so no legend.
  function timeline(host, buckets) {
    var W = 900, H = 180, L = 36, B = 22, T = 6;
    if (!buckets.length) return empty(host, W, H);
    var s = svg(host, W, H), max = Math.max.apply(null, buckets.map(function (b) { return b.count; })) || 1;
    var n = buckets.length, bw = (W - L) / n, plotH = H - B - T;
    var grid = el("g", { "class": "grid" }, s), axis = el("g", { "class": "axis" }, s);
    [0, 0.5, 1].forEach(function (f) {
      var y = T + plotH - f * plotH;
      el("line", { x1: L, x2: W, y1: y, y2: y }, grid);
      text(axis, L - 6, y + 3, Math.round(f * max), "", "end");
    });
    buckets.forEach(function (b, i) {
      if (!b.count) return;
      var h = Math.max((b.count / max) * plotH, 1);
      var r = el("rect", { "class": "bar", x: L + i * bw + 1, y: T + plotH - h, width: Math.max(bw - 2, 1), height: h, rx: Math.min(2, bw / 4) }, s);
      r.addEventListener("mousemove", function (ev) { showTip(ev, "<b>" + b.count + "</b> · " + esc(b.ts.replace("T", " ")) + " UTC"); });
      r.addEventListener("mouseleave", hideTip);
    });
    var step = Math.max(1, Math.ceil(n / 8));
    buckets.forEach(function (b, i) { if (i % step === 0) text(axis, L + i * bw + bw / 2, H - 6, b.ts.slice(5).replace("T", " "), "", "middle"); });
  }

  // Horizontal ranked bars: [{name, count}]
  function hbars(host, items, opts) {
    opts = opts || {};
    var W = 400, rowH = 22, H = Math.max(rowH * items.length + 4, 40);
    if (!items.length) return empty(host, W, 80);
    var s = svg(host, W, H), max = Math.max.apply(null, items.map(function (i) { return i.count; })) || 1;
    var labelW = 150;
    items.forEach(function (it, i) {
      var y = 2 + i * rowH, w = ((W - labelW - 50) * it.count) / max;
      text(s, labelW - 8, y + 15, (opts.label ? opts.label(it) : it.name).slice(0, 22), "hbar-label", "end");
      var r = el("rect", { "class": (opts.cls ? opts.cls(it) : "hbar"), x: labelW, y: y + 4, width: Math.max(w, 2), height: rowH - 8, rx: 2 }, s);
      r.addEventListener("mousemove", function (ev) { showTip(ev, "<b>" + it.count + "</b> · " + esc(opts.label ? opts.label(it) : it.name)); });
      r.addEventListener("mouseleave", hideTip);
      text(s, labelW + w + 6, y + 15, it.count, "hbar-value");
    });
  }

  function countryName(code) { return (window.peephole.countryNames && window.peephole.countryNames[code]) || code; }

  // Choropleth: one hue, five quantised steps, legend beside it.
  function map(host, legend, data) {
    var src = host.getAttribute("data-src");
    fetch(src).then(function (r) { return r.text(); }).then(function (svgText) {
      host.innerHTML = svgText;
      var max = data.max || 0;
      var thresholds = [0, 1, Math.max(2, Math.ceil(max * 0.1)), Math.max(3, Math.ceil(max * 0.35)), Math.max(4, Math.ceil(max * 0.7))];
      function bin(v) { if (!v) return 0; for (var b = 4; b >= 1; b--) if (v >= thresholds[b]) return b; return 1; }
      host.querySelectorAll(".country").forEach(function (p) {
        var code = p.id, v = data.countries[code] || 0;
        p.setAttribute("data-bin", bin(v));
        p.addEventListener("mousemove", function (ev) { showTip(ev, "<b>" + esc(countryName(code)) + "</b> · " + v + (v === 1 ? " IP" : " IPs")); });
        p.addEventListener("mouseleave", hideTip);
        p.addEventListener("click", function () { location.href = "/ips?country=" + code; });
      });
      if (legend) {
        legend.innerHTML = "";
        function span(lo, hi) { return lo === hi ? String(lo) : lo + "–" + hi; }
        var labels = ["0", span(1, thresholds[2] - 1), span(thresholds[2], thresholds[3] - 1), span(thresholds[3], thresholds[4] - 1), thresholds[4] + "+"];
        for (var b = 0; b < 5; b++) {
          if (!max && b > 0) break;
          var item = document.createElement("span"), sw = document.createElement("i");
          sw.className = "swatch"; sw.setAttribute("data-bin", b);
          item.appendChild(sw); item.appendChild(document.createTextNode(max ? labels[b] : "no data"));
          legend.appendChild(item);
        }
      }
    }).catch(function () {});
  }

  function sparkline(host, values) {
    var W = 240, H = 40, n = values.length || 1, s = svg(host, W, H), max = Math.max.apply(null, values) || 1, bw = W / n;
    s.setAttribute("preserveAspectRatio", "none");
    s.removeAttribute("height");
    values.forEach(function (v, i) { var h = (v / max) * H; el("rect", { x: i * bw + 0.5, y: H - h, width: Math.max(bw - 1, 1), height: h }, s); });
  }

  function boot() {
    var wall = document.getElementById("wall");
    if (wall) {
      var range = wall.getAttribute("data-range") || "24h";
      fetch("/api/stats?range=" + range).then(function (r) { return r.json(); }).then(function (st) {
        timeline(document.getElementById("chart-timeline"), fillBuckets(st.timeline, range));
        hbars(document.getElementById("chart-severity"), st.severity_distribution, { label: function (i) { return "severity " + i.name; }, cls: function (i) { return "sev-bar-" + i.name; } });
        hbars(document.getElementById("chart-labels"), st.top_labels.slice(0, 10));
        fetch("/api/countries").then(function (r) { return r.json(); }).then(function (names) {
          window.peephole.countryNames = names;
          hbars(document.getElementById("chart-countries"), st.top_countries.slice(0, 10), { label: function (i) { return countryName(i.name); } });
          return fetch("/api/map?range=" + range).then(function (r) { return r.json(); });
        }).then(function (m) {
          map(document.getElementById("map"), document.getElementById("map-legend"), m);
        }).catch(function () {});
      }).catch(function () {});
    }
    document.querySelectorAll("[data-sparkline]").forEach(function (h) {
      try { sparkline(h, JSON.parse(h.getAttribute("data-sparkline"))); } catch (e) {}
    });
  }
  window.peephole = window.peephole || {};
  window.peephole.charts = { timeline: timeline, hbars: hbars, map: map, sparkline: sparkline };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
