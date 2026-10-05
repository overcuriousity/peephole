// The link graph of /admin/links/<kind>/<value>: the focus, the IPs it was
// seen on and what else links them. Data from /admin/api/links/graph; laid
// out here (one ring per hop, then a short seeded relax) and drawn as SVG.
// Pan by dragging, zoom with the wheel or a pinch, click a node for its
// facts, Expand to fetch its neighbours.
(function () {
  "use strict";
  var host = document.querySelector("[data-link-graph]");
  if (!host) return;
  var NS = "http://www.w3.org/2000/svg";
  var form = document.querySelector("[data-graph-controls]");
  var status = document.querySelector("[data-graph-status]");
  var panel = document.querySelector("[data-link-panel] [data-selected]");
  var kinds = JSON.parse(host.getAttribute("data-kinds") || "{}");
  var focusId = host.getAttribute("data-focus");
  var calm = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var RING = 150, LINK = 90, MAX = 400;
  var g = { nodes: [], edges: [], byId: {} };
  var view = { x: 0, y: 0, k: 1 };
  var W = 800, H = 520, svg, vp, selected = null;

  function el(name, attrs, parent) {
    var e = document.createElementNS(NS, name);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function short(v) { return String(v).replace(/^SHA256:/, "").slice(0, 8); }
  function label(n) {
    if (n.kind === "ip") return n.value;
    if (n.kind === "group") return n.ips + " IPs";
    return n.kind + " " + short(n.value);
  }
  function say(t) { if (status) status.textContent = t; }

  // ---- data -------------------------------------------------------------
  function options() {
    var types = [], depth = "2";
    if (form) {
      form.querySelectorAll("input[name=types]:checked").forEach(function (c) { types.push(c.value); });
      depth = form.querySelector("select[name=depth]").value;
    }
    return { types: types.join(","), depth: depth };
  }
  function load(focus, depth, all) {
    var o = options();
    var url = "/admin/api/links/graph?focus=" + encodeURIComponent(focus) +
      "&types=" + encodeURIComponent(o.types) + "&depth=" + (depth || o.depth) + (all ? "&all=1" : "");
    return fetch(url, { credentials: "same-origin", headers: { accept: "application/json" } })
      .then(function (r) {
        if (!r.ok || r.redirected) throw new Error(r.redirected ? "signed out?" : "HTTP " + r.status);
        return r.json();
      });
  }
  function edgeKey(a, b) { return a < b ? a + "\n" + b : b + "\n" + a; }
  // Union by id; new nodes start at `at` (their parent) and are marked.
  function merge(data, at) {
    var keys = {};
    g.edges.forEach(function (e) { keys[edgeKey(e.a, e.b)] = 1; });
    data.nodes.forEach(function (n) {
      if (g.byId[n.id]) return;
      n.fresh = true;
      if (at) { n.x = at.x; n.y = at.y; }
      g.byId[n.id] = n;
      g.nodes.push(n);
    });
    data.edges.forEach(function (e) {
      var k = edgeKey(e.a, e.b);
      if (!keys[k] && g.byId[e.a] && g.byId[e.b]) { keys[k] = 1; g.edges.push(e); }
    });
  }
  function drop(id) {
    g.nodes = g.nodes.filter(function (n) { return n.id !== id; });
    g.edges = g.edges.filter(function (e) { return e.a !== id && e.b !== id; });
    delete g.byId[id];
  }

  // ---- layout -----------------------------------------------------------
  function neighbours(id) {
    var out = [];
    g.edges.forEach(function (e) { if (e.a === id) out.push(e.b); else if (e.b === id) out.push(e.a); });
    return out;
  }
  // Hops from the focus (breadth-first) and each node's parent.
  function rings() {
    var hop = {}, parent = {}, q = [focusId];
    hop[focusId] = 0;
    while (q.length) {
      var id = q.shift();
      neighbours(id).forEach(function (m) {
        if (hop[m] === undefined) { hop[m] = hop[id] + 1; parent[m] = id; q.push(m); }
      });
    }
    return { hop: hop, parent: parent };
  }
  // Fresh nodes: rings by hop, ordered by their parent's angle; then a
  // seeded relax that moves only fresh nodes (targets tx/ty). Settled nodes
  // stay put.
  function layout() {
    var r = rings(), seed = 7;
    function rnd() { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; }
    var f = g.byId[focusId];
    if (f && f.x === undefined) { f.x = 0; f.y = 0; }
    var byHop = {};
    g.nodes.forEach(function (n) {
      var h = r.hop[n.id] === undefined ? 1 : r.hop[n.id];
      n.ring = h * RING;
      if (!n.fresh || n.id === focusId) return;
      (byHop[h] = byHop[h] || []).push(n);
    });
    function angle(n) { var p = g.byId[r.parent[n.id]]; return p && (p.x || p.y) ? Math.atan2(p.y, p.x) : 0; }
    Object.keys(byHop).forEach(function (h) {
      var list = byHop[h].sort(function (a, b) { return angle(a) - angle(b); });
      list.forEach(function (n, i) {
        if (n.x !== undefined) return; // started at its parent (expand)
        var a = (i / list.length) * 2 * Math.PI;
        n.x = Math.cos(a) * h * RING; n.y = Math.sin(a) * h * RING;
      });
    });
    function px(b) { return b.tx !== undefined ? b.tx : b.x; }
    function py(b) { return b.ty !== undefined ? b.ty : b.y; }
    var moving = g.nodes.filter(function (n) { return n.fresh && n.id !== focusId; });
    moving.forEach(function (n) { n.tx = n.x + (rnd() - 0.5) * 4; n.ty = n.y + (rnd() - 0.5) * 4; });
    for (var it = 0; it < 150; it++) {
      var cool = 1 - it / 150;
      moving.forEach(function (a) {
        var fx = 0, fy = 0;
        g.nodes.forEach(function (b) {
          if (a === b) return;
          var dx = a.tx - px(b), dy = a.ty - py(b), d2 = dx * dx + dy * dy + 1;
          if (d2 < 40000) { fx += dx * 900 / d2; fy += dy * 900 / d2; }
        });
        neighbours(a.id).forEach(function (id) {
          var b = g.byId[id], dx = px(b) - a.tx, dy = py(b) - a.ty, d = Math.sqrt(dx * dx + dy * dy) || 1;
          fx += dx * (d - LINK) / d * 0.05; fy += dy * (d - LINK) / d * 0.05;
        });
        var d0 = Math.sqrt(a.tx * a.tx + a.ty * a.ty) || 1;
        fx += a.tx / d0 * (a.ring - d0) * 0.05; fy += a.ty / d0 * (a.ring - d0) * 0.05;
        var sp = Math.sqrt(fx * fx + fy * fy), lim = 12 * cool + 0.5;
        if (sp > lim) { fx *= lim / sp; fy *= lim / sp; }
        a.tx += fx; a.ty += fy;
      });
    }
  }
  function land() {
    g.nodes.forEach(function (n) {
      if (n.tx !== undefined) { n.x = n.tx; n.y = n.ty; }
      delete n.tx; delete n.ty; n.fresh = false;
    });
  }

  // ---- drawing ----------------------------------------------------------
  function transform() { vp.setAttribute("transform", "translate(" + view.x + "," + view.y + ") scale(" + view.k + ")"); }
  // Frame the graph; never zoom in past 1×.
  function fit() {
    if (!g.nodes.length || !vp) return;
    var x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    g.nodes.forEach(function (n) { x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x); y1 = Math.max(y1, n.y); });
    view.k = Math.max(0.2, Math.min(1, W / (x1 - x0 + 220), H / (y1 - y0 + 80)));
    view.x = W / 2 - (x0 + x1 + 80) / 2 * view.k; view.y = H / 2 - (y0 + y1) / 2 * view.k;
    transform();
  }
  function place(e, a, b) {
    [e.hit, e.line].forEach(function (l) { l.setAttribute("x1", a.x); l.setAttribute("y1", a.y); l.setAttribute("x2", b.x); l.setAttribute("y2", b.y); });
  }
  function draw() {
    host.innerHTML = "";
    W = host.clientWidth || 800; H = host.clientHeight || 520;
    svg = el("svg", { viewBox: "0 0 " + W + " " + H }, host);
    vp = el("g", { "class": "viewport" }, svg);
    var ge = el("g", { "class": "edges" }, vp), gn = el("g", { "class": "nodes" }, vp);
    g.edges.forEach(function (e) {
      e.el = el("g", { "class": "edge" + (e.identity ? "" : " soft") }, ge);
      e.hit = el("line", { "class": "hit" }, e.el);
      e.line = el("line", { "class": "line" }, e.el);
      el("title", {}, e.hit).textContent = (e.identity ? "identity" : "software") + " link";
      place(e, g.byId[e.a], g.byId[e.b]);
    });
    g.nodes.forEach(function (n) {
      var kind = n.kind === "ip" || n.kind === "group" ? n.kind : "item k-" + n.kind;
      n.el = el("g", { "class": "node " + kind + (n.identity ? "" : " soft") + (n.id === focusId ? " focus" : "") + (n === selected ? " selected" : ""), tabindex: 0, "data-id": n.id }, gn);
      if (n.kind === "ip") el("circle", { r: 6 }, n.el);
      else if (n.kind === "group") el("circle", { r: 13 }, n.el);
      else el("rect", { x: -7, y: -7, width: 14, height: 14, rx: 3 }, n.el);
      el("text", { x: n.kind === "group" ? 17 : 11, y: 4 }, n.el).textContent = label(n);
      el("title", {}, n.el).textContent = (n.kind === "group" ? n.ips + " IPs with " + (kinds[n.of] || n.of) : (kinds[n.kind] || "IP")) + " " + n.value;
      n.el.setAttribute("transform", "translate(" + n.x + "," + n.y + ")");
      n.el.addEventListener("mouseenter", function () { light(n, true); });
      n.el.addEventListener("mouseleave", function () { light(n, false); });
      n.el.addEventListener("focus", function () { light(n, true); });
      n.el.addEventListener("blur", function () { light(n, false); });
      n.el.addEventListener("click", function () { select(n); });
      n.el.addEventListener("keydown", function (ev) { if (ev.key === "Enter") select(n); });
    });
    wire();
  }
  // Fresh nodes glide from where they start to their place.
  function settle() {
    var moving = g.nodes.filter(function (n) { return n.fresh && n.tx !== undefined; });
    if (calm || !moving.length) { land(); draw(); transform(); return Promise.resolve(); }
    var from = moving.map(function (n) { return [n.x, n.y]; }), t0 = performance.now();
    return new Promise(function (resolve) {
      function step(t) {
        var p = Math.min(1, (t - t0) / 250), s = 1 - Math.pow(1 - p, 3);
        moving.forEach(function (n, i) {
          n.x = from[i][0] + (n.tx - from[i][0]) * s; n.y = from[i][1] + (n.ty - from[i][1]) * s;
          n.el.setAttribute("transform", "translate(" + n.x + "," + n.y + ")");
        });
        g.edges.forEach(function (e) { place(e, g.byId[e.a], g.byId[e.b]); });
        if (p < 1) requestAnimationFrame(step);
        else { land(); resolve(); }
      }
      requestAnimationFrame(step);
    });
  }
  function light(n, on) {
    var near = {}; near[n.id] = 1;
    neighbours(n.id).forEach(function (id) { near[id] = 1; });
    svg.classList.toggle("has-hl", on);
    g.nodes.forEach(function (m) { m.el.classList.toggle("hl", on && !!near[m.id]); });
    g.edges.forEach(function (e) { e.el.classList.toggle("hl", on && (e.a === n.id || e.b === n.id)); });
  }

  // ---- panel ------------------------------------------------------------
  function href(n) {
    if (n.kind === "ip") return "/ip/" + encodeURIComponent(n.value);
    return "/admin/links/" + n.kind + "/" + encodeURIComponent(n.value) + location.search;
  }
  function select(n) {
    if (selected && selected.el) selected.el.classList.remove("selected");
    selected = n; n.el.classList.add("selected");
    if (!panel) return;
    var name = n.kind === "group" ? n.ips + " IPs with this " + (kinds[n.of] || n.of) : (kinds[n.kind] || "IP");
    var rows = [["Value", n.value]];
    if (n.ips != null && n.kind !== "group") rows.push(["IPs", n.ips]);
    if (n.sightings != null) rows.push([n.kind === "ip" ? "Requests" : "Sightings", n.sightings]);
    if (n.last_seen) rows.push(["Last seen", n.last_seen]);
    if (n.country) rows.push(["Country", n.country]);
    panel.innerHTML = "<h3>" + esc(name) + "</h3><dl class=\"kv\">" + rows.map(function (r) {
      return "<dt>" + esc(r[0]) + "</dt><dd>" + esc(r[1]) + "</dd>";
    }).join("") + "</dl><p class=\"link-actions\">" +
      (n.kind === "group" ? "" : "<a class=\"btn btn-sm\" href=\"" + esc(href(n)) + "\">Open</a> ") +
      "<button type=\"button\" class=\"btn btn-sm\" data-expand>Expand</button></p>";
    panel.hidden = false;
    panel.querySelector("[data-expand]").addEventListener("click", function () { expand(n); });
  }
  function expand(n) {
    var group = n.kind === "group", focus = group ? n.of + ":" + n.value : n.id;
    say("Loading…");
    load(focus, 1, group).then(function (data) {
      var at = { x: n.x, y: n.y };
      if (group) { drop(n.id); if (selected === n) selected = null; }
      merge(data, at);
      layout(); draw(); transform();
      return settle().then(function () { report(data); });
    }).catch(fail);
  }

  // ---- pan and zoom -----------------------------------------------------
  function wire() {
    var pts = {}, last = null, pinch = null;
    function local(ev) { var b = svg.getBoundingClientRect(); return { x: (ev.clientX - b.left) * W / b.width, y: (ev.clientY - b.top) * H / b.height }; }
    function zoomAt(p, k) {
      k = Math.max(0.2, Math.min(4, k));
      view.x = p.x - (p.x - view.x) * k / view.k; view.y = p.y - (p.y - view.y) * k / view.k; view.k = k;
      transform();
    }
    svg.addEventListener("wheel", function (ev) { ev.preventDefault(); zoomAt(local(ev), view.k * Math.pow(1.0015, -ev.deltaY)); }, { passive: false });
    svg.addEventListener("pointerdown", function (ev) {
      if (ev.target.closest(".node")) return;
      pts[ev.pointerId] = local(ev); svg.setPointerCapture(ev.pointerId);
      var ids = Object.keys(pts);
      if (ids.length === 2) { var a = pts[ids[0]], b = pts[ids[1]]; pinch = { d: Math.hypot(a.x - b.x, a.y - b.y) || 1, k: view.k }; last = null; }
      else last = pts[ev.pointerId];
    });
    svg.addEventListener("pointermove", function (ev) {
      if (!pts[ev.pointerId]) return;
      var p = local(ev); pts[ev.pointerId] = p;
      var ids = Object.keys(pts);
      if (pinch && ids.length === 2) {
        var a = pts[ids[0]], b = pts[ids[1]];
        zoomAt({ x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }, pinch.k * Math.hypot(a.x - b.x, a.y - b.y) / pinch.d);
      } else if (last) { view.x += p.x - last.x; view.y += p.y - last.y; last = p; transform(); }
    });
    function up(ev) { delete pts[ev.pointerId]; if (Object.keys(pts).length < 2) pinch = null; last = null; }
    svg.addEventListener("pointerup", up);
    svg.addEventListener("pointercancel", up);
  }

  // ---- boot -------------------------------------------------------------
  function report(data) {
    var t = g.nodes.length + " nodes";
    if (data && data.truncated) t += " · stopped at " + MAX + " nodes: lower the depth or untick kinds";
    say(t);
  }
  function fail(e) { say("Could not load the graph (" + e.message + ")."); }
  function reload() {
    say("Loading…");
    load(focusId).then(function (data) {
      g = { nodes: [], edges: [], byId: {} }; selected = null;
      merge(data, null);
      layout(); land();
      draw(); fit(); report(data);
    }).catch(fail);
  }
  if (form) {
    form.hidden = false;
    form.addEventListener("submit", function (ev) { ev.preventDefault(); });
    form.addEventListener("change", function () {
      var o = options();
      history.replaceState(null, "", "?types=" + encodeURIComponent(o.types) + "&depth=" + o.depth);
      reload();
    });
    var fb = form.querySelector("[data-graph-fit]");
    if (fb) fb.addEventListener("click", fit);
  }
  var lastW = window.innerWidth;
  window.addEventListener("resize", function () {
    if (window.innerWidth === lastW || !g.nodes.length) return;
    lastW = window.innerWidth; draw(); fit();
  });
  reload();
})();
