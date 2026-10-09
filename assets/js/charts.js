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
  var tip = document.createElement("div"); tip.className = "tooltip"; tip.setAttribute("aria-hidden", "true"); document.body.appendChild(tip);
  function showTip(ev, html) {
    tip.innerHTML = html; tip.style.display = "block";
    // Keep the tooltip on screen near the right and bottom edges.
    var x = ev.clientX + 12, y = ev.clientY + 12, r = tip.getBoundingClientRect();
    if (x + r.width > window.innerWidth - 8) x = ev.clientX - r.width - 12;
    if (y + r.height > window.innerHeight - 8) y = ev.clientY - r.height - 12;
    tip.style.left = Math.max(4, x) + "px"; tip.style.top = Math.max(4, y) + "px";
  }
  function hideTip() { tip.style.display = "none"; }
  // Hover shows the tooltip; keyboard and screen-reader users get the
  // same numbers from the table twin beside each chart.
  function hover(node, html) {
    node.addEventListener("mousemove", function (ev) { showTip(ev, html()); });
    node.addEventListener("mouseleave", hideTip);
  }
  // A failed request rejects instead of handing an error page to .json().
  function get(url, as) {
    return fetch(url, { credentials: "same-origin" }).then(function (r) {
      if (!r.ok) throw new Error(url + ": " + r.status);
      return as === "text" ? r.text() : r.json();
    });
  }
  function failed(host) { if (host) { host.innerHTML = ""; var p = document.createElement("p"); p.className = "empty-note muted"; p.textContent = "Could not load the data. Reload to try again."; host.appendChild(p); } }
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
    // "all" is daily from the first day with requests, so quiet days show as gaps.
    if (range === "all" && buckets.length) spec = [Math.max(0, Math.round((Date.now() - Date.parse(buckets[0].ts + "T00:00:00Z")) / 86400e3)), false];
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
      var hit = el("rect", { "class": "col-hit", x: L + i * slot, y: T, width: slot, height: plotH }, s);
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
      var hit = el("rect", { "class": "col-hit", x: 0, y: y, width: W, height: rowH }, s);
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
        var c = el("rect", { "class": "cell", "data-bin": binOf(v, max), x: L + h * cw, y: T + d * ch, width: cw, height: ch, rx: 3 }, s);
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
    get(host.getAttribute("data-src"), "text").then(function (svgText) {
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
    }).catch(function () { failed(host); });
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
        var r = el("rect", { "class": "day " + (v ? "sev-fill-" + Math.max(0, Math.min(4, v.max_severity)) : "day-empty"), x: L + w * cell, y: T + d * cell, width: cell, height: cell, rx: 2 }, s);
        (function (key, v) {
          hover(r, function () { return v ? "<b>" + fmt(v.count) + "</b> requests · " + key + "<br>highest severity " + v.max_severity : key + " · no requests"; });
        })(key, v);
      }
    }
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

  // Lines and bands over hours: `xs` are hours (Unix / 3600), each layer
  // {cls, values} (a line; null breaks it) or {cls, lo, hi} (a band).
  // `tip(i)` is the tooltip of column i.
  function hourChart(host, xs, layers, tip, opts) {
    opts = opts || {};
    var W = Math.max(widthOf(host, 800), 240), H = opts.height || 200, L = 46, B = 22, T = 10, R = 8;
    var vals = [];
    layers.forEach(function (l) { (l.values || []).concat(l.hi || []).forEach(function (v) { if (v != null) vals.push(v); }); });
    if (!xs.length || !vals.length) return empty(host, W, H);
    var s = svg(host, W, H), max = niceMax(Math.max.apply(null, vals)), plotH = H - B - T;
    var x0 = xs[0], span = Math.max(1, xs[xs.length - 1] - x0);
    var X = function (h) { return L + ((h - x0) / span) * (W - L - R); }, Y = function (v) { return T + plotH - (v / max) * plotH; };
    var grid = el("g", { "class": "grid" }, s), axis = el("g", { "class": "axis" }, s);
    [0, 0.5, 1].forEach(function (f) {
      var y = T + plotH - f * plotH;
      el("line", { x1: L, x2: W - R, y1: y, y2: y }, grid);
      text(axis, L - 6, y + 3, opts.fmt ? opts.fmt(f * max) : compact(Math.round(f * max)), "", "end");
    });
    // A tick at each UTC midnight in range.
    for (var h = Math.ceil(x0 / 24) * 24; h <= xs[xs.length - 1]; h += 24) {
      var d = new Date(h * 3600e3);
      text(axis, X(h), H - 6, pad2(d.getUTCMonth() + 1) + "-" + pad2(d.getUTCDate()), "", "middle");
    }
    // Runs of consecutive non-null values, one path each.
    function runs(get) {
      var out = [], cur = [];
      xs.forEach(function (h, i) { var v = get(i); if (v == null) { if (cur.length) out.push(cur); cur = []; } else cur.push([X(h), v, i]); });
      if (cur.length) out.push(cur);
      return out;
    }
    layers.forEach(function (l) {
      if (l.lo) {
        runs(function (i) { return l.lo[i] != null && l.hi[i] != null ? l.hi[i] : null; }).forEach(function (r) {
          var top = r.map(function (p) { return p[0].toFixed(1) + "," + Y(p[1]).toFixed(1); });
          var bot = r.slice().reverse().map(function (p) { return p[0].toFixed(1) + "," + Y(l.lo[p[2]]).toFixed(1); });
          el("polygon", { "class": l.cls, points: top.concat(bot).join(" ") }, s);
        });
      } else {
        runs(function (i) { return l.values[i]; }).forEach(function (r) {
          if (r.length === 1) { el("circle", { "class": l.cls + " dot", cx: r[0][0], cy: Y(r[0][1]), r: 2.5 }, s); return; }
          el("path", { "class": l.cls, d: r.map(function (p, k) { return (k ? "L" : "M") + p[0].toFixed(1) + "," + Y(p[1]).toFixed(1); }).join("") }, s);
        });
      }
    });
    var slot = (W - L - R) / Math.max(1, xs.length);
    xs.forEach(function (h, i) {
      var hit = el("rect", { "class": "col-hit", x: X(h) - slot / 2, y: T, width: slot, height: plotH }, s);
      hover(hit, function () { return tip(i); });
    });
  }

  function hourLabel(h) { var d = new Date(h * 3600e3); return d.getUTCFullYear() + "-" + pad2(d.getUTCMonth() + 1) + "-" + pad2(d.getUTCDate()) + " " + pad2(d.getUTCHours()) + ":00 UTC"; }
  function credits(mc) { return mc == null ? null : mc / 1000; }
  function cr(v) { return v == null ? "—" : v.toFixed(2); }

  // Cluster › Credits: one good's price (this node, members' band and
  // median) and its demand and supply; the seg buttons pick the good.
  function bootMarket(host) {
    var data = JSON.parse(host.getAttribute("data-market")), dsHost = document.querySelector("[data-market-ds]"), twin = document.querySelector("[data-market-table]");
    var good = host.getAttribute("data-good");
    function draw() {
      var series = data[good];
      if (!series) return;
      var pts = series.points, xs = pts.map(function (p) { return p.hour; });
      var own = pts.map(function (p) { return credits(p.own_mc); }), lo = pts.map(function (p) { return credits(p.lo_mc); }), hi = pts.map(function (p) { return credits(p.hi_mc); }), med = pts.map(function (p) { return credits(p.median_mc); });
      hourChart(host, xs, [{ cls: "band", lo: lo, hi: hi }, { cls: "line median", values: med }, { cls: "line own", values: own }], function (i) {
        return "<b>" + esc(series.label) + "</b> · " + hourLabel(xs[i]) + "<br>this node: <b>" + cr(own[i]) + "</b><br>members: " + (lo[i] == null ? "—" : cr(lo[i]) + "–" + cr(hi[i]) + " (median " + cr(med[i]) + ")");
      }, { fmt: function (v) { return v.toFixed(v < 1 ? 2 : 1); } });
      if (dsHost) {
        var dem = pts.map(function (p) { return p.demand; }), sup = pts.map(function (p) { return p.supply; });
        hourChart(dsHost, xs, [{ cls: "line supply", values: sup }, { cls: "line demand", values: dem }], function (i) {
          return hourLabel(xs[i]) + "<br>demand <b>" + dem[i].toFixed(1) + "</b> · supply <b>" + sup[i].toFixed(1) + "</b> per hour";
        }, { height: 120, fmt: function (v) { return compact(Math.round(v)); } });
      }
      if (twin) {
        var t = "<table><caption>" + esc(series.label) + ": price per hour (UTC)</caption><tr><th>Hour</th><th>This node</th><th>Members, lowest</th><th>Median</th><th>Highest</th><th>Demand</th><th>Supply</th></tr>";
        pts.forEach(function (p, i) { t += "<tr><td>" + hourLabel(p.hour) + "</td><td>" + cr(own[i]) + "</td><td>" + cr(lo[i]) + "</td><td>" + cr(med[i]) + "</td><td>" + cr(hi[i]) + "</td><td>" + p.demand.toFixed(1) + "</td><td>" + p.supply.toFixed(1) + "</td></tr>"; });
        twin.innerHTML = t + "</table>";
      }
      document.querySelectorAll(".market-goods [data-pick-good]").forEach(function (a) { if (a.getAttribute("data-pick-good") === good) a.setAttribute("aria-current", "true"); else a.removeAttribute("aria-current"); });
    }
    document.addEventListener("click", function (e) {
      var a = e.target.closest && e.target.closest("[data-pick-good]");
      if (!a || !data[a.getAttribute("data-pick-good")]) return;
      good = a.getAttribute("data-pick-good");
      draw();
    });
    draw(); onWidthChange(draw);
  }

  // This node's money per day: income stacked (pool, sales) beside what
  // it spent. [{day, pool, sales, spent}]
  function flow(host, days) {
    var W = Math.max(widthOf(host, 500), 240), H = 180, L = 46, B = 22, T = 8;
    var max = 0;
    days.forEach(function (d) { max = Math.max(max, d.pool + d.sales, d.spent); });
    if (!max) return empty(host, W, H);
    var s = svg(host, W, H), top = niceMax(max), plotH = H - B - T, slot = (W - L) / days.length, bw = Math.min(18, slot / 3);
    var grid = el("g", { "class": "grid" }, s), axis = el("g", { "class": "axis" }, s);
    [0, 0.5, 1].forEach(function (f) { var y = T + plotH - f * plotH; el("line", { x1: L, x2: W, y1: y, y2: y }, grid); text(axis, L - 6, y + 3, compact(Math.round(f * top)), "", "end"); });
    days.forEach(function (d, i) {
      var x = L + i * slot + slot / 2 - bw - 1, y = T + plotH;
      [["pool", d.pool], ["sales", d.sales]].forEach(function (k) {
        if (!k[1]) return;
        var h = Math.max((k[1] / top) * plotH, 1); y -= h;
        el("rect", { "class": "seg k-" + k[0], x: x, y: y, width: bw, height: h }, s);
      });
      if (d.spent) { var h2 = Math.max((d.spent / top) * plotH, 1); el("rect", { "class": "seg k-spent", x: x + bw + 2, y: T + plotH - h2, width: bw, height: h2 }, s); }
      var hit = el("rect", { "class": "col-hit", x: L + i * slot, y: T, width: slot, height: plotH }, s);
      hover(hit, function () { return "<b>" + esc(d.day) + "</b><br>pool " + cr(d.pool) + " · sales " + cr(d.sales) + "<br>spent <b>" + cr(d.spent) + "</b>"; });
      text(axis, L + i * slot + slot / 2, H - 6, d.day, "", "middle");
    });
    var twin = document.querySelector("[data-flow-table]");
    if (twin) {
      var t = "<table><caption>This node's credits per day</caption><tr><th>Day</th><th>Pool</th><th>Sales</th><th>Spent</th></tr>";
      days.forEach(function (d) { t += "<tr><td>" + esc(d.day) + "</td><td>" + cr(d.pool) + "</td><td>" + cr(d.sales) + "</td><td>" + cr(d.spent) + "</td></tr>"; });
      twin.innerHTML = t + "</table>";
    }
  }

  function boot() {
    var mk = document.querySelector("[data-market]");
    if (mk) { try { bootMarket(mk); } catch (e) {} }
    var fl = document.querySelector("[data-flow]");
    if (fl) { try { var fd = JSON.parse(fl.getAttribute("data-flow")); var drawFlow = function () { flow(fl, fd); }; drawFlow(); onWidthChange(drawFlow); } catch (e) {} }
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
      return get("/api/stats?range=" + range).then(function (next) {
        st = next; buckets = fillBuckets(st.timeline, range);
        drawStats(); drawCountries();
      });
    }
    load().then(function () {
      onWidthChange(function () { drawStats(); drawCountries(); });
      return get("/api/countries");
    }).then(function (names) {
      window.peephole.countryNames = names;
      drawCountries();
      return get("/api/map?range=" + range);
    }).then(function (m) {
      mapData = m;
      map(document.getElementById("map"), document.getElementById("map-legend"), m);
    }).catch(function () { if (!st) failed(hosts.tl); });
  }

  window.peephole = window.peephole || {};
  window.peephole.charts = { timeline: timeline, hbars: hbars, map: map, sparkline: sparkline, heatmap: heatmap, calendar: calendar };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
