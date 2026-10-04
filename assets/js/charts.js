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
  // Charts are drawn at the host's own width (1 unit = 1 CSS px), so text
  // keeps its size on a phone instead of shrinking with a fixed viewBox.
  function widthOf(host, fallback) { return Math.round(host.clientWidth) || fallback; }
  function empty(host, w, h) { var s = svg(host, w, h); text(s, w / 2, h / 2, "no data in this range", "empty-note", "middle"); }
  var tip = document.createElement("div"); tip.className = "tooltip"; tip.setAttribute("role", "status"); document.body.appendChild(tip);
  function showTip(ev, html) {
    tip.innerHTML = html; tip.style.display = "block";
    // Keep the tooltip on screen near the right and bottom edges.
    var x = ev.clientX + 12, y = ev.clientY + 12, r = tip.getBoundingClientRect();
    if (x + r.width > window.innerWidth - 8) x = ev.clientX - r.width - 12;
    if (y + r.height > window.innerHeight - 8) y = ev.clientY - r.height - 12;
    tip.style.left = Math.max(4, x) + "px"; tip.style.top = Math.max(4, y) + "px";
  }
  function hideTip() { tip.style.display = "none"; }
  // Hover and keyboard focus show the same tooltip.
  function hover(node, html) {
    node.addEventListener("mousemove", function (ev) { showTip(ev, html()); });
    node.addEventListener("mouseleave", hideTip);
    node.addEventListener("focus", function () { var r = node.getBoundingClientRect(); showTip({ clientX: r.left + r.width / 2, clientY: r.top }, html()); });
    node.addEventListener("blur", hideTip);
  }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function fmt(n) { return Number(n).toLocaleString("en-US"); }
  function compact(n) { return n >= 1e6 ? (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M" : n >= 1e4 ? Math.round(n / 1e3) + "k" : n >= 1e3 ? (n / 1e3).toFixed(1) + "k" : String(n); }
  // A clean axis maximum: 1, 2 or 5 × 10^k at or above `v`.
  function niceMax(v) {
    if (v <= 0) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(v))), m = v / p;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p;
  }
  // A rect with only its top corners rounded: the data end of a column.
  function topRounded(x, y, w, h, r) {
    r = Math.max(0, Math.min(r, w / 2, h));
    return "M" + x + "," + (y + h) + "V" + (y + r) + "Q" + x + "," + y + " " + (x + r) + "," + y +
      "H" + (x + w - r) + "Q" + (x + w) + "," + y + " " + (x + w) + "," + (y + r) + "V" + (y + h) + "Z";
  }
  function rightRounded(x, y, w, h, r) {
    r = Math.max(0, Math.min(r, h / 2, w));
    return "M" + x + "," + y + "H" + (x + w - r) + "Q" + (x + w) + "," + y + " " + (x + w) + "," + (y + r) +
      "V" + (y + h - r) + "Q" + (x + w) + "," + (y + h) + " " + (x + w - r) + "," + (y + h) + "H" + x + "Z";
  }

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
    buckets.forEach(function (b) { byKey[b.ts] = b; });
    var out = [], now = new Date(), stepMs = spec[1] ? 3600e3 : 86400e3;
    // A rolling window touches n+1 calendar buckets (the oldest is partial).
    for (var i = spec[0]; i >= 0; i--) {
      var k = bucketKey(new Date(now.getTime() - i * stepMs), spec[1]);
      out.push(byKey[k] || { ts: k, count: 0, by_severity: [0, 0, 0, 0, 0] });
    }
    return out;
  }

  // Columns over time, each stacked by severity 0 (bottom) .. 4 (top).
  // [{ts, count, by_severity:[5]}]. Legend lives in the page markup.
  function timeline(host, buckets, opts) {
    opts = opts || {};
    var W = Math.max(widthOf(host, 900), 240), H = opts.height || 190, L = 40, B = 22, T = 8;
    if (!buckets.length || !buckets.some(function (b) { return b.count; })) return empty(host, W, H);
    var s = svg(host, W, H), max = niceMax(Math.max.apply(null, buckets.map(function (b) { return b.count; })));
    var n = buckets.length, slot = (W - L) / n, plotH = H - B - T;
    var bw = Math.min(24, Math.max(slot - 2, 1)), off = (slot - bw) / 2;
    var grid = el("g", { "class": "grid" }, s), axis = el("g", { "class": "axis" }, s);
    [0, 0.5, 1].forEach(function (f) {
      var y = T + plotH - f * plotH;
      el("line", { x1: L, x2: W, y1: y, y2: y }, grid);
      text(axis, L - 6, y + 3, compact(Math.round(f * max)), "", "end");
    });
    var gap = 2;
    buckets.forEach(function (b, i) {
      var x = L + i * slot + off, y = T + plotH, sev = b.by_severity || [b.count, 0, 0, 0, 0];
      var top = -1;
      for (var k = 4; k >= 0; k--) if (sev[k]) { top = k; break; }
      for (var j = 0; j <= 4; j++) {
        if (!sev[j]) continue;
        var h = (sev[j] / max) * plotH, g = h > gap * 2 && j !== top ? gap : 0;
        if (h < 1) h = 1;
        y -= h;
        if (j === top) el("path", { "class": "seg sev-fill-" + j, d: topRounded(x, y, bw, h, 3) }, s);
        else el("rect", { "class": "seg sev-fill-" + j, x: x, y: y + g, width: bw, height: Math.max(h - g, 1) }, s);
      }
      // One hit target per column, the full plot height (bigger than the mark).
      var hit = el("rect", { "class": "col-hit", x: L + i * slot, y: T, width: slot, height: plotH, tabindex: b.count ? 0 : -1 }, s);
      hover(hit, function () {
        var rows = [];
        for (var j = 4; j >= 0; j--) if (sev[j]) rows.push("severity " + j + ": <b>" + fmt(sev[j]) + "</b>");
        return "<b>" + fmt(b.count) + "</b> requests · " + esc(b.ts.replace("T", " ")) + " UTC" + (rows.length ? "<br>" + rows.join("<br>") : "");
      });
    });
    // About one tick label per 80px: "10-03 09:00" in 10px mono is ~70px.
    var step = Math.max(1, Math.ceil(n / Math.max(2, Math.min(8, Math.floor((W - L) / 80)))));
    buckets.forEach(function (b, i) { if (i % step === 0) text(axis, L + i * slot + slot / 2, H - 6, b.ts.slice(5).replace("T", " "), "", "middle"); });
  }

  // Area sparkline behind the hero tile: counts only, no axes.
  function tileSpark(host, values) {
    if (!host || values.length < 2) return;
    var W = Math.max(widthOf(host, 300), 60), H = 36, s = svg(host, W, H), max = Math.max.apply(null, values) || 1;
    s.setAttribute("preserveAspectRatio", "none");
    var pts = values.map(function (v, i) { return [(i / (values.length - 1)) * W, H - 2 - (v / max) * (H - 6)]; });
    var line = pts.map(function (p, i) { return (i ? "L" : "M") + p[0].toFixed(1) + "," + p[1].toFixed(1); }).join("");
    el("path", { "class": "area", d: line + "L" + W + "," + H + "L0," + H + "Z" }, s);
    el("path", { "class": "line", d: line }, s);
  }

  // Horizontal ranked bars: [{name, count}]
  function hbars(host, items, opts) {
    opts = opts || {};
    var W = Math.max(widthOf(host, 400), 220), rowH = 24, H = Math.max(rowH * items.length + 4, 40);
    if (!items.length) return empty(host, W, 80);
    var s = svg(host, W, H), max = Math.max.apply(null, items.map(function (i) { return i.count; })) || 1;
    var labelW = Math.min(150, Math.round(W * 0.4)), maxChars = Math.floor((labelW - 8) / 6.5), valueW = 52;
    items.forEach(function (it, i) {
      var y = 2 + i * rowH, w = Math.max(((W - labelW - valueW) * it.count) / max, 2), label = opts.label ? opts.label(it) : it.name;
      text(s, labelW - 8, y + 16, clip(label, maxChars), "hbar-label", "end");
      el("path", { "class": (opts.cls ? opts.cls(it) : "hbar"), d: rightRounded(labelW, y + 6, w, rowH - 12, 3) }, s);
      var hit = el("rect", { "class": "col-hit", x: 0, y: y, width: W, height: rowH, tabindex: 0 }, s);
      hover(hit, function () { return "<b>" + fmt(it.count) + "</b> · " + esc(label); });
      text(s, labelW + w + 6, y + 16, compact(it.count), "hbar-value");
    });
  }

  function clip(s, n) { s = String(s); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  function countryName(code) { return (window.peephole.countryNames && window.peephole.countryNames[code]) || code; }

  // Five quantised steps of one hue: 0, then four bins up to `max`.
  function binOf(v, max) { return !v || !max ? 0 : Math.min(4, Math.max(1, Math.ceil((v / max) * 4))); }
  function rampLegend(legend, max, unit) {
    if (!legend) return;
    legend.innerHTML = "";
    if (!max) { legend.textContent = "no data"; return; }
    var lo = document.createElement("span"); lo.className = "ramp-label"; lo.textContent = "0";
    var ramp = document.createElement("span"); ramp.className = "ramp";
    for (var i = 0; i < 5; i++) ramp.appendChild(document.createElement("i"));
    var hi = document.createElement("span"); hi.className = "ramp-label"; hi.textContent = fmt(max) + " " + unit;
    legend.appendChild(lo); legend.appendChild(ramp); legend.appendChild(hi);
  }

  // Weekday × hour heatmap: rows Monday..Sunday, columns 00..23 UTC.
  var DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  function heatmap(host, legend, matrix) {
    var W = Math.max(widthOf(host, 600), 240), L = 34, T = 4, B = 18;
    var cw = (W - L) / 24, ch = Math.min(Math.max(cw, 14), 26), H = T + ch * 7 + B;
    var max = 0;
    matrix.forEach(function (row) { row.forEach(function (v) { if (v > max) max = v; }); });
    if (!max) { rampLegend(legend, 0); return empty(host, W, H); }
    var s = svg(host, W, H), axis = el("g", { "class": "axis" }, s);
    matrix.forEach(function (row, d) {
      text(axis, L - 6, T + d * ch + ch / 2 + 3, DAYS[d], "", "end");
      row.forEach(function (v, h) {
        var c = el("rect", { "class": "cell", "data-bin": binOf(v, max), x: L + h * cw, y: T + d * ch, width: cw, height: ch, rx: 3, tabindex: v ? 0 : -1 }, s);
        hover(c, function () { return "<b>" + fmt(v) + "</b> requests · " + DAYS[d] + " " + pad2(h) + ":00–" + pad2(h) + ":59 UTC"; });
      });
    });
    var every = cw < 22 ? 6 : 3;
    for (var h = 0; h < 24; h += every) text(axis, L + h * cw + cw / 2, H - 4, pad2(h), "", "middle");
    rampLegend(legend, max, "requests");
  }

  // Choropleth: one hue, five quantised steps; hovering a country lights its
  // row in the ranked list beside the map (#map-rank), and the other way round.
  function map(host, legend, data) {
    var paint = function () {
      var max = data.max || 0;
      host.querySelectorAll(".country").forEach(function (p) {
        var v = data.countries[p.id] || 0;
        p.setAttribute("data-bin", binOf(v, max));
      });
      rampLegend(legend, max, "IPs");
    };
    if (host.querySelector("svg")) { paint(); return; }
    fetch(host.getAttribute("data-src")).then(function (r) { return r.text(); }).then(function (svgText) {
      host.innerHTML = svgText;
      host.querySelectorAll(".country").forEach(function (p) {
        var code = p.id;
        p.addEventListener("mousemove", function (ev) {
          var v = data.countries[code] || 0;
          showTip(ev, "<b>" + esc(countryName(code)) + "</b> · " + fmt(v) + (v === 1 ? " IP" : " IPs"));
          hot(code, true);
        });
        p.addEventListener("mouseleave", function () { hideTip(); hot(code, false); });
        p.addEventListener("click", function () { location.href = "/ips?country=" + code; });
      });
      paint();
    }).catch(function () {});
    function hot(code, on) {
      var path = host.querySelector('[id="' + code + '"]'), list = document.getElementById("map-rank");
      if (path) path.classList.toggle("is-hot", on);
      var li = list && list.querySelector('[data-country="' + code + '"]');
      if (li) li.classList.toggle("is-hot", on);
    }
    // Delegated, so the list keeps working after a refresh swaps it.
    ["mouseover", "mouseout"].forEach(function (type) {
      document.addEventListener(type, function (e) {
        var li = e.target.closest && e.target.closest("#map-rank [data-country]");
        if (li) hot(li.getAttribute("data-country"), type === "mouseover");
      });
    });
    // Repaint with fresh counts (auto-refresh) without fetching the map again.
    map.update = function (next) { data = next; paint(); };
  }

  function sparkline(host, values) {
    var W = 240, H = 40, n = values.length || 1, s = svg(host, W, H), max = Math.max.apply(null, values) || 1, bw = W / n;
    s.setAttribute("preserveAspectRatio", "none");
    s.removeAttribute("height");
    values.forEach(function (v, i) { var h = (v / max) * H; el("rect", { x: i * bw + 0.5, y: H - h, width: Math.max(bw - 1, 1), height: h }, s); });
  }

  // Activity calendar: one column per week (Monday on top), a cell per day
  // coloured by that day's highest severity. [{day, count, max_severity}]
  function calendar(host, days, nDays) {
    var byDay = {};
    days.forEach(function (d) { byDay[d.day] = d; });
    var today = new Date(), start = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - (nDays - 1)));
    // Back to the Monday of the first week.
    start.setUTCDate(start.getUTCDate() - ((start.getUTCDay() + 6) % 7));
    var weeks = Math.ceil(((today - start) / 86400e3 + 1) / 7);
    var W = Math.max(widthOf(host, 700), 240), L = 30, T = 16, cell = Math.min(20, (W - L) / weeks), H = T + cell * 7 + 2;
    var s = svg(host, W, H), axis = el("g", { "class": "axis" }, s), lastMonth = -1;
    [0, 2, 4].forEach(function (d) { text(axis, L - 6, T + d * cell + cell / 2 + 3, DAYS[d], "", "end"); });
    for (var w = 0; w < weeks; w++) {
      for (var d = 0; d < 7; d++) {
        var t = new Date(start.getTime() + (w * 7 + d) * 86400e3);
        if (t > today) continue;
        var key = t.getUTCFullYear() + "-" + pad2(t.getUTCMonth() + 1) + "-" + pad2(t.getUTCDate()), v = byDay[key];
        if (d === 0 && t.getUTCMonth() !== lastMonth) {
          lastMonth = t.getUTCMonth();
          if (w < weeks - 2) text(axis, L + w * cell, 10, t.toLocaleString("en-US", { month: "short", timeZone: "UTC" }), "", "start");
        }
        var r = el("rect", { "class": "day " + (v ? "sev-fill-" + Math.max(0, Math.min(4, v.max_severity)) : "day-empty"), x: L + w * cell, y: T + d * cell, width: cell, height: cell, rx: 2, tabindex: v ? 0 : -1 }, s);
        (function (key, v) {
          hover(r, function () { return v ? "<b>" + fmt(v.count) + "</b> requests · " + key + "<br>highest severity " + v.max_severity : key + " · no requests"; });
        })(key, v);
      }
    }
  }

  // Fingerprint ↔ IP graph: a small force layout (repulsion, springs,
  // centring), run to rest once, then drawn; nodes can be dragged.
  function fpGraph(host, clusters) {
    var W = Math.max(widthOf(host, 800), 260), H = host.clientHeight || 420;
    var nodes = [], edges = [], byKey = {};
    // A seeded generator: the same clusters lay out the same on every load.
    var seed = 7;
    function rnd() { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; }
    function node(key, kind, label) {
      if (!byKey[key]) { byKey[key] = { key: key, kind: kind, label: label, x: W / 2 + (rnd() - 0.5) * W * 0.8, y: H / 2 + (rnd() - 0.5) * H * 0.8, vx: 0, vy: 0, links: [] }; nodes.push(byKey[key]); }
      return byKey[key];
    }
    // Start each fingerprint at its own point on an ellipse and its IPs in a
    // ring around it, so the force pass only relaxes an already sorted layout
    // (from random starts, linked clusters end up tangled).
    clusters.forEach(function (c, ci) {
      var a = (ci / clusters.length) * 2 * Math.PI, cx = W / 2 + Math.cos(a) * W * 0.3 * (clusters.length > 1), cy = H / 2 + Math.sin(a) * H * 0.28 * (clusters.length > 1);
      var f = node("fp:" + c.hash, "fp", c.hash.slice(0, 8));
      f.x = cx; f.y = cy; f.count = c.count;
      c.ips.forEach(function (ip, ii) {
        var fresh = !byKey["ip:" + ip], n = node("ip:" + ip, "ip", ip), b = (ii / c.ips.length) * 2 * Math.PI + rnd() * 0.3;
        if (fresh) { n.x = cx + Math.cos(b) * 70; n.y = cy + Math.sin(b) * 70; }
        edges.push([f, n]); f.links.push(n); n.links.push(f);
      });
    });
    if (!nodes.length) return;
    // Spacing: room for an IP label, smaller when crowded.
    var k = Math.max(40, Math.min(90, Math.sqrt((W * H) / nodes.length) * 0.4));
    for (var it = 0; it < 300; it++) {
      var cool = 1 - it / 300;
      for (var i = 0; i < nodes.length; i++) {
        var a = nodes[i];
        for (var j = i + 1; j < nodes.length; j++) {
          var b = nodes[j], dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy + 0.01, f = (k * k) / d2;
          a.vx += dx * f * 0.06; a.vy += dy * f * 0.06; b.vx -= dx * f * 0.06; b.vy -= dy * f * 0.06;
        }
      }
      edges.forEach(function (e) {
        var dx = e[1].x - e[0].x, dy = e[1].y - e[0].y, d = Math.sqrt(dx * dx + dy * dy) || 1, f = (d - k) / d * 0.1;
        e[0].vx += dx * f; e[0].vy += dy * f; e[1].vx -= dx * f; e[1].vy -= dy * f;
      });
      nodes.forEach(function (n) {
        n.vx += (W / 2 - n.x) * 0.002; n.vy += (H / 2 - n.y) * 0.002;
        var sp = Math.sqrt(n.vx * n.vx + n.vy * n.vy), lim = 20 * cool + 1;
        if (sp > lim) { n.vx *= lim / sp; n.vy *= lim / sp; }
        n.x = Math.max(16, Math.min(W - 110, n.x + n.vx)); // room for the label n.y = Math.max(16, Math.min(H - 16, n.y + n.vy));
        n.vx *= 0.6; n.vy *= 0.6;
      });
    }
    var s = svg(host, W, H);
    s.removeAttribute("height"); s.removeAttribute("width");
    var ge = el("g", {}, s), gn = el("g", {}, s);
    var lines = edges.map(function (e) { return el("line", { "class": "edge" }, ge); });
    function place() {
      edges.forEach(function (e, i) { lines[i].setAttribute("x1", e[0].x); lines[i].setAttribute("y1", e[0].y); lines[i].setAttribute("x2", e[1].x); lines[i].setAttribute("y2", e[1].y); });
      nodes.forEach(function (n) {
        if (n.kind === "fp") { n.el.setAttribute("x", n.x - 7); n.el.setAttribute("y", n.y - 7); } else { n.el.setAttribute("cx", n.x); n.el.setAttribute("cy", n.y); }
        n.text.setAttribute("x", n.x + 10); n.text.setAttribute("y", n.y + 3);
      });
    }
    function focus(n, on) {
      var near = {}; near[n.key] = 1; n.links.forEach(function (m) { near[m.key] = 1; });
      nodes.forEach(function (m) { m.el.classList.toggle("is-dim", on && !near[m.key]); m.text.classList.toggle("is-dim", on && !near[m.key]); });
      edges.forEach(function (e, i) { lines[i].classList.toggle("is-dim", on && e[0] !== n && e[1] !== n); });
    }
    nodes.forEach(function (n) {
      n.el = n.kind === "fp" ? el("rect", { "class": "n-fp", width: 14, height: 14, rx: 3, tabindex: 0 }, gn) : el("circle", { "class": "n-ip", r: 6, tabindex: 0 }, gn);
      n.text = text(gn, 0, 0, n.label, "n-label");
      hover(n.el, function () { return n.kind === "fp" ? "fingerprint <b>" + esc(n.label) + "…</b> · " + n.links.length + " IPs · " + fmt(n.count) + " sightings" : "<b>" + esc(n.label) + "</b> · " + n.links.length + " shared fingerprint" + (n.links.length === 1 ? "" : "s"); });
      n.el.addEventListener("mouseenter", function () { focus(n, true); });
      n.el.addEventListener("mouseleave", function () { focus(n, false); });
      var drag = null;
      n.el.addEventListener("pointerdown", function (ev) { drag = { x: ev.clientX, y: ev.clientY, moved: false }; n.el.setPointerCapture(ev.pointerId); });
      n.el.addEventListener("pointermove", function (ev) {
        if (!drag) return;
        var sc = W / s.getBoundingClientRect().width;
        n.x += (ev.clientX - drag.x) * sc; n.y += (ev.clientY - drag.y) * sc;
        if (Math.abs(ev.clientX - drag.x) + Math.abs(ev.clientY - drag.y) > 2) drag.moved = true;
        drag.x = ev.clientX; drag.y = ev.clientY; place();
      });
      n.el.addEventListener("pointerup", function () {
        var moved = drag && drag.moved; drag = null;
        if (!moved) location.href = n.kind === "ip" ? "/ip/" + encodeURIComponent(n.label) : "#" + n.key.slice(3);
      });
      n.el.addEventListener("keydown", function (ev) { if (ev.key === "Enter") location.href = n.kind === "ip" ? "/ip/" + encodeURIComponent(n.label) : "#" + n.key.slice(3); });
    });
    place();
  }

  // Redraw after the viewport width settles (rotation, window resize); a
  // height-only change (mobile URL bar) does not count.
  function onWidthChange(fn) {
    var last = window.innerWidth, timer;
    window.addEventListener("resize", function () {
      if (window.innerWidth === last) return;
      last = window.innerWidth;
      clearTimeout(timer);
      timer = setTimeout(fn, 150);
    });
  }

  // The screen-reader twin of the timeline and the heatmap.
  function tables(host, buckets, matrix) {
    if (!host) return;
    var h = "<table><caption>Requests over time by severity (UTC)</caption><tr><th>Time</th><th>Total</th><th>Sev 0</th><th>Sev 1</th><th>Sev 2</th><th>Sev 3</th><th>Sev 4</th></tr>";
    buckets.forEach(function (b) { if (b.count) h += "<tr><td>" + esc(b.ts) + "</td><td>" + b.count + "</td><td>" + b.by_severity.join("</td><td>") + "</td></tr>"; });
    h += "</table><table><caption>Requests per weekday and hour (UTC)</caption><tr><th>Day</th>";
    for (var i = 0; i < 24; i++) h += "<th>" + pad2(i) + "</th>";
    h += "</tr>";
    matrix.forEach(function (row, d) { h += "<tr><th>" + DAYS[d] + "</th><td>" + row.join("</td><td>") + "</td></tr>"; });
    host.innerHTML = h + "</table>";
  }

  function boot() {
    var wall = document.getElementById("wall");
    if (wall) bootWall(wall);
    document.querySelectorAll("[data-sparkline]").forEach(function (h) {
      try { sparkline(h, JSON.parse(h.getAttribute("data-sparkline"))); } catch (e) {}
    });
    var week = document.querySelector("[data-week]");
    if (week) {
      try {
        var wb = fillBuckets(JSON.parse(week.getAttribute("data-week")), "7d"), cal = document.querySelector("[data-calendar]");
        var cd = cal ? JSON.parse(cal.getAttribute("data-calendar")) : [], nd = cal ? parseInt(cal.getAttribute("data-days") || "182", 10) : 182;
        var drawIp = function () { timeline(week, wb, { height: 150 }); if (cal) calendar(cal, cd, nd); };
        drawIp(); onWidthChange(drawIp);
      } catch (e) {}
    }
    var fg = document.querySelector("[data-fp-graph]");
    if (fg) { try { var cl = JSON.parse(fg.getAttribute("data-fp-graph")); fpGraph(fg, cl); onWidthChange(function () { fpGraph(fg, cl); }); } catch (e) {} }
  }

  function bootWall(wall) {
    var range = wall.getAttribute("data-range") || "24h", st = null, buckets = [], mapData = null;
    var hosts = { tl: document.getElementById("chart-timeline"), hm: document.getElementById("chart-heatmap"), sev: document.getElementById("chart-severity"), labels: document.getElementById("chart-labels"), countries: document.getElementById("chart-countries") };
    function drawStats() {
      timeline(hosts.tl, buckets);
      heatmap(hosts.hm, document.getElementById("heatmap-legend"), st.heatmap || []);
      tileSpark(document.getElementById("spark-requests"), buckets.map(function (b) { return b.count; }));
      if (hosts.sev) hbars(hosts.sev, st.severity_distribution, { label: function (i) { return "severity " + i.name; }, cls: function (i) { return "sev-fill-" + i.name; } });
      if (hosts.labels) hbars(hosts.labels, (st.top_labels || []).slice(0, 10));
      tables(document.getElementById("stats-tables"), buckets, st.heatmap || []);
    }
    function drawCountries() {
      if (!window.peephole.countryNames) return;
      hbars(hosts.countries, st.top_countries.slice(0, 10), { label: function (i) { return countryName(i.name); } });
    }
    function load() {
      return fetch("/api/stats?range=" + range).then(function (r) { return r.json(); }).then(function (next) {
        st = next; buckets = fillBuckets(st.timeline, range);
        drawStats(); drawCountries();
      });
    }
    load().then(function () {
      onWidthChange(function () { drawStats(); drawCountries(); });
      return fetch("/api/countries").then(function (r) { return r.json(); });
    }).then(function (names) {
      window.peephole.countryNames = names;
      drawCountries();
      return fetch("/api/map?range=" + range).then(function (r) { return r.json(); });
    }).then(function (m) {
      mapData = m;
      map(document.getElementById("map"), document.getElementById("map-legend"), m);
    }).catch(function () {});

    // Soft refresh: while the tab is visible, re-read the page and the
    // aggregates once per cache lifetime and swap the server-rendered
    // regions in place. No new endpoint; anonymous reads hit the cache.
    var every = Math.max(15, parseInt(wall.getAttribute("data-refresh") || "60", 10)) * 1000, updated = document.querySelector("[data-updated]");
    function refresh() {
      if (document.hidden) return;
      fetch(location.pathname + location.search, { headers: { accept: "text/html" }, credentials: "same-origin" })
        .then(function (r) { if (!r.ok) throw new Error(r.status); return r.text(); })
        .then(function (html) {
          var doc = new DOMParser().parseFromString(html, "text/html");
          document.querySelectorAll("[data-region]").forEach(function (old) {
            var fresh = doc.querySelector('[data-region="' + old.getAttribute("data-region") + '"]');
            if (fresh) old.replaceWith(document.importNode(fresh, true));
          });
          if (window.peephole.ago) window.peephole.ago();
          return load();
        })
        .then(function () {
          if (mapData) return fetch("/api/map?range=" + range).then(function (r) { return r.json(); }).then(function (m) { if (map.update) map.update(m); });
        })
        .then(function () {
          if (updated) updated.textContent = "updated " + new Date().toISOString().slice(11, 19) + " UTC";
        })
        .catch(function () {});
    }
    setInterval(refresh, every);
    document.addEventListener("visibilitychange", function () { if (!document.hidden) refresh(); });
  }

  window.peephole = window.peephole || {};
  window.peephole.charts = { timeline: timeline, hbars: hbars, map: map, sparkline: sparkline, heatmap: heatmap, calendar: calendar, fpGraph: fpGraph };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
