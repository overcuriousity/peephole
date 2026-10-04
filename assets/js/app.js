(function () {
  "use strict";
  // Theme toggle: system → light → dark → system.
  var btn = document.querySelector("[data-theme-toggle]");
  if (btn) {
    var label = btn.querySelector("[data-theme-label]");
    var render = function () {
      var t = document.documentElement.getAttribute("data-theme") || "auto";
      if (label) label.textContent = t === "auto" ? "Auto" : t === "dark" ? "Dark" : "Light";
    };
    btn.addEventListener("click", function () {
      var cur = document.documentElement.getAttribute("data-theme") || "auto";
      var next = cur === "auto" ? "light" : cur === "light" ? "dark" : "auto";
      if (next === "auto") document.documentElement.removeAttribute("data-theme");
      else document.documentElement.setAttribute("data-theme", next);
      try { if (next === "auto") localStorage.removeItem("peephole.theme"); else localStorage.setItem("peephole.theme", next); } catch (e) {}
      render();
    });
    render();
  }
  // Confirmation dialogs for destructive forms.
  document.querySelectorAll("[data-confirm]").forEach(function (b) {
    b.addEventListener("click", function () {
      var d = document.getElementById(b.getAttribute("data-confirm"));
      if (d && d.showModal) d.showModal();
    });
  });
  document.querySelectorAll("dialog [data-close]").forEach(function (b) {
    b.addEventListener("click", function () { b.closest("dialog").close(); });
  });
  // Click a [data-copy] panel (invite, config key) to copy its text.
  document.querySelectorAll("[data-copy]").forEach(function (el) {
    if (!navigator.clipboard) return;
    el.title = "Click to copy";
    el.addEventListener("click", function () {
      navigator.clipboard.writeText(el.textContent.trim()).then(function () {
        el.setAttribute("data-copied", "");
        el.title = "Copied";
        setTimeout(function () { el.removeAttribute("data-copied"); el.title = "Click to copy"; }, 1500);
      }, function () {});
    });
  });
  // One-shot notice the server set after an action; shown once, then cleared.
  [["peephole_flash", "success"], ["peephole_flash_error", "warning"]].forEach(function (f) {
    var fm = document.cookie.match(new RegExp("(?:^|; )" + f[0] + "=([^;]*)"));
    if (!fm) return;
    document.cookie = f[0] + "=; Path=/; Max-Age=0; SameSite=Strict";
    var main = document.querySelector("main");
    if (main) {
      var note = document.createElement("div");
      note.className = "banner banner-" + f[1];
      try { note.textContent = decodeURIComponent(fm[1].replace(/\+/g, " ")); } catch (e) { note.textContent = ""; }
      if (note.textContent) main.insertBefore(note, main.firstChild);
    }
  });
  // WebAuthn ceremonies (moved out of inline scripts for CSP).
  function b64uToBuf(s) { return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), function (c) { return c.charCodeAt(0); }).buffer; }
  function bufToB64u(b) { return btoa(String.fromCharCode.apply(null, new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  var wa = document.querySelector("[data-webauthn]");
  if (wa) {
    var mode = wa.getAttribute("data-webauthn"), msg = wa.querySelector("[data-msg]");
    wa.querySelector("[data-go]").addEventListener("click", async function () {
      msg.textContent = "";
      try {
        if (mode === "login") {
          var start = await fetch("/login/start", { method: "POST" });
          if (!start.ok) throw new Error("login start failed: " + start.status);
          var opts = (await start.json()).publicKey;
          opts.challenge = b64uToBuf(opts.challenge);
          if (opts.allowCredentials) opts.allowCredentials = opts.allowCredentials.map(function (c) { c.id = b64uToBuf(c.id); return c; });
          var cred = await navigator.credentials.get({ publicKey: opts });
          var body = { credential: { id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type, response: {
            authenticatorData: bufToB64u(cred.response.authenticatorData), clientDataJSON: bufToB64u(cred.response.clientDataJSON),
            signature: bufToB64u(cred.response.signature), userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null } } };
          var fin = await fetch("/login/finish", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
          if (fin.ok) location.href = "/admin"; else msg.textContent = "authentication failed (" + fin.status + ")";
        } else {
          var tokenEl = wa.querySelector("[data-token]"), labelEl = wa.querySelector("[data-label]");
          var payload = { label: (labelEl && labelEl.value.trim()) || null };
          if (tokenEl) payload.setup_token = tokenEl.value.trim();
          var start2 = await fetch("/enroll/start", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
          if (!start2.ok) throw new Error("enroll start failed: " + start2.status);
          var copts = (await start2.json()).publicKey;
          copts.challenge = b64uToBuf(copts.challenge);
          copts.user.id = b64uToBuf(copts.user.id);
          if (copts.excludeCredentials) copts.excludeCredentials = copts.excludeCredentials.map(function (c) { c.id = b64uToBuf(c.id); return c; });
          var ccred = await navigator.credentials.create({ publicKey: copts });
          var cbody = { credential: { id: ccred.id, rawId: bufToB64u(ccred.rawId), type: ccred.type, response: {
            attestationObject: bufToB64u(ccred.response.attestationObject), clientDataJSON: bufToB64u(ccred.response.clientDataJSON) },
            extensions: ccred.getClientExtensionResults ? ccred.getClientExtensionResults() : {} } };
          var fin2 = await fetch("/enroll/finish", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(cbody) });
          if (fin2.ok) location.href = "/admin/keys"; else msg.textContent = "enrollment failed (" + fin2.status + ")";
        }
      } catch (e) { msg.textContent = e.message || String(e); }
    });
  }

  // Body panel: text ⇄ hex dump.
  document.querySelectorAll("[data-hex-toggle]").forEach(function (b) {
    var pre = document.getElementById(b.getAttribute("data-hex-toggle")), text = pre.getAttribute("data-text"), hex = null, on = false;
    b.addEventListener("click", function () {
      on = !on;
      if (on && hex === null) {
        // Decode the raw bytes from base64 so binary payloads and CR/LF show
        // correctly; the data-text attribute is lossy UTF-8 with normalised
        // newlines. Fall back to the text encoding if base64 is absent.
        var bytes;
        var b64 = pre.getAttribute("data-b64");
        if (b64 != null) {
          var bin = atob(b64);
          bytes = new Uint8Array(bin.length);
          for (var k = 0; k < bin.length; k++) bytes[k] = bin.charCodeAt(k);
        } else {
          bytes = new TextEncoder().encode(text);
        }
        var lines = [];
        for (var i = 0; i < bytes.length; i += 16) {
          var chunk = Array.prototype.slice.call(bytes, i, i + 16);
          lines.push(i.toString(16).padStart(8, "0") + "  " + chunk.map(function (x) { return x.toString(16).padStart(2, "0"); }).join(" ").padEnd(48) + "  " +
            chunk.map(function (x) { return x >= 32 && x < 127 ? String.fromCharCode(x) : "."; }).join(""));
        }
        hex = lines.join("\n");
      }
      pre.textContent = on ? hex : text;
      b.textContent = on ? "text" : "hex";
    });
  });

  // Live scan queue over SSE.
  var qt = document.querySelector("[data-queue]");
  if (qt && window.EventSource) {
    var live = document.querySelector("[data-live]"), liveLabel = live && live.querySelector("[data-live-label]");
    var tbody = qt.querySelector("tbody"), limit = parseInt(qt.getAttribute("data-limit") || "25", 10);
    var setLive = function (state, label) { if (live) { live.setAttribute("data-state", state); if (liveLabel) liveLabel.textContent = label; } };
    var cell = function (cls, html) { var td = document.createElement("td"); if (cls) td.className = cls; td.innerHTML = html; return td; };
    var esc = function (s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); };
    var row = function (j) {
      var tr = document.createElement("tr"); tr.setAttribute("data-job", j.id);
      tr.appendChild(cell("mono", "#" + esc(j.id)));
      tr.appendChild(cell("ip", '<a href="/ip/' + esc(j.ip) + '">' + esc(j.ip) + "</a>"));
      tr.appendChild(cell("", esc(j.level)));
      tr.appendChild(cell("", '<span class="badge badge-status" data-status="' + esc(j.status) + '">' + esc(j.status) + "</span>"));
      tr.appendChild(cell("ts", esc(j.queued_at)));
      tr.appendChild(cell("ts", esc(j.finished_at)));
      tr.appendChild(cell("mono wrap", esc(j.error)));
      tr.appendChild(cell("muted", esc(j.scanner) + (j.arbiter ? '<span class="node-via"> via ' + esc(j.arbiter) + "</span>" : "")));
      return tr;
    };
    // The page's status/level filter applies to live rows too.
    // The level compares as a number, as the server parses it ("03" is 3).
    var fStatus = qt.getAttribute("data-filter-status") || "", lv = (qt.getAttribute("data-filter-level") || "").trim();
    var fLevel = /^[+-]?\d+$/.test(lv) ? parseInt(lv, 10) : NaN;
    var matches = function (j) { return (!fStatus || j.status === fStatus) && (isNaN(fLevel) || Number(j.level) === fLevel); };
    var COLS = 8;
    var apply = function (j) {
      var existing = tbody.querySelector('[data-job="' + j.id + '"]');
      if (!matches(j)) { if (existing) existing.remove(); return; }
      var empty = tbody.querySelector("[data-empty]"); if (empty) empty.remove();
      var fresh = row(j);
      if (existing) {
        // Update in place; the row keeps its position (rows are id-ordered).
        tbody.replaceChild(fresh, existing);
      } else {
        // Insert in descending-id order (newest first), matching the snapshot,
        // so an update for an older job does not jump to the top.
        var before = null, jid = Number(j.id);
        var rows = tbody.querySelectorAll("[data-job]");
        for (var i = 0; i < rows.length; i++) {
          if (Number(rows[i].getAttribute("data-job")) < jid) { before = rows[i]; break; }
        }
        tbody.insertBefore(fresh, before);
      }
      while (tbody.children.length > limit) tbody.removeChild(tbody.lastChild);
    };
    var snapshot = function (jobs) {
      tbody.innerHTML = "";
      jobs = jobs.filter(matches);
      jobs.slice(0, limit).forEach(function (j) { tbody.appendChild(row(j)); });
      if (!jobs.length) { var tr = document.createElement("tr"); tr.setAttribute("data-empty", ""); var td = cell("empty", "Queue empty."); td.setAttribute("colspan", String(COLS)); tr.appendChild(td); tbody.appendChild(tr); }
    };
    var es = new EventSource(qt.getAttribute("data-src"));
    es.addEventListener("open", function () { setLive("open", "live"); });
    es.addEventListener("error", function () {
      // A permanently closed stream (session ended → the reconnect is
      // redirected to /login and is not an event stream) stays stuck on
      // "reconnecting". Surface it instead, and reload so the redirect lands.
      if (es.readyState === EventSource.CLOSED) {
        setLive("closed", "disconnected");
        setTimeout(function () { location.reload(); }, 2000);
      } else {
        setLive("reconnecting", "reconnecting…");
      }
    });
    es.addEventListener("snapshot", function (ev) { try { snapshot(JSON.parse(ev.data)); } catch (e) {} });
    es.addEventListener("job", function (ev) { try { apply(JSON.parse(ev.data)); } catch (e) {} });
  }

  // Bulk selection: header box toggles the page, "Delete selected" needs a tick.
  function refreshBulkButtons() {
    document.querySelectorAll("[data-needs-checked]").forEach(function (b) {
      var form = document.getElementById(b.getAttribute("data-needs-checked"));
      b.disabled = !form || !form.querySelector('input[name="ids"]:checked');
    });
  }
  document.querySelectorAll("[data-check-all]").forEach(function (h) {
    var form = document.getElementById(h.getAttribute("data-check-all"));
    h.addEventListener("change", function () {
      if (form) form.querySelectorAll('input[name="ids"]').forEach(function (c) { c.checked = h.checked; });
      refreshBulkButtons();
    });
  });
  document.addEventListener("change", function (e) { if (e.target && e.target.name === "ids") refreshBulkButtons(); });
  refreshBulkButtons();

  // Relative times: <time datetime="YYYY-MM-DD HH:MM:SS" data-ago> (UTC)
  // shows "5 min" and keeps counting; the exact time is in the tooltip.
  function ago() {
    var now = Date.now();
    document.querySelectorAll("time[data-ago]").forEach(function (t) {
      var at = Date.parse(t.getAttribute("datetime").replace(" ", "T") + "Z");
      if (isNaN(at)) return;
      var s = Math.max(0, Math.round((now - at) / 1000));
      t.textContent = s < 60 ? s + " s" : s < 3600 ? Math.floor(s / 60) + " min" : s < 86400 ? Math.floor(s / 3600) + " h" : Math.floor(s / 86400) + " d";
      if (!t.title) t.title = t.getAttribute("datetime") + " UTC";
    });
  }
  ago();
  setInterval(ago, 5000);

  // Live "Recent activity" on the wall (admin): batches of new requests
  // over SSE, newest on top, the table capped at its server-rendered size.
  var rt = document.querySelector("[data-recent]");
  if (rt && window.EventSource) {
    var rLive = rt.closest("section").querySelector("[data-live]"), rLabel = rLive && rLive.querySelector("[data-live-label]");
    var rBody = rt.querySelector("tbody"), rMax = 50;
    var rSet = function (state, label) { if (rLive) { rLive.setAttribute("data-state", state); if (rLabel) rLabel.textContent = label; } };
    var resc = function (s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); };
    var flag = function (cc) { return cc && /^[A-Z]{2}$/.test(cc) ? String.fromCodePoint(0x1f1e6 + cc.charCodeAt(0) - 65, 0x1f1e6 + cc.charCodeAt(1) - 65) : ""; };
    var rRow = function (r) {
      var tr = document.createElement("tr"), sev = Math.max(0, Math.min(4, r.severity | 0));
      tr.setAttribute("data-sev", sev); tr.className = "is-new";
      var chips = (r.labels || []).map(function (l, i) { var f = (r.families || [])[i]; return '<span class="badge badge-label' + (f && f !== "other" ? " badge-cat-" + resc(f) : "") + '">' + resc(l) + "</span>"; }).join("") +
        (r.owasp || []).map(function (o) { return '<span class="badge badge-owasp">' + resc(o) + "</span>"; }).join("");
      tr.innerHTML = '<td class="ts">' + resc(r.ts) + '</td><td class="ip"><a href="/ip/' + resc(r.ip) + '">' + resc(r.ip) + "</a>" + (r.country ? ' <span class="flag">' + flag(r.country) + "</span>" : "") +
        '</td><td class="mono">' + resc(r.method) + '</td><td class="path"><a href="/admin/requests/' + resc(r.id) + '">' + resc(r.path) + "</a></td>" +
        '<td><span class="sev sev-' + sev + '" title="severity ' + sev + '">' + sev + '</span></td><td><span class="chips">' + chips + "</span></td>";
      return tr;
    };
    // EventSource reconnects to the URL it was opened with, so a reconnect
    // replays rows after the page's cursor: keep only ids not shown yet.
    var rLast = parseInt((rt.getAttribute("data-src").match(/after=(\d+)/) || [0, "0"])[1], 10);
    var res = new EventSource(rt.getAttribute("data-src"));
    res.addEventListener("open", function () { rSet("open", "live"); });
    res.addEventListener("error", function () {
      // Closed for good (the session ended): reload so the redirect lands.
      if (res.readyState === EventSource.CLOSED) { rSet("closed", "disconnected"); setTimeout(function () { location.reload(); }, 2000); } else { rSet("reconnecting", "reconnecting…"); }
    });
    res.addEventListener("requests", function (ev) {
      var rows; try { rows = JSON.parse(ev.data); } catch (e) { return; }
      rows = rows.filter(function (r) { return r.id > rLast; });
      if (!rows.length) return;
      rLast = rows[rows.length - 1].id;
      var empty = rBody.querySelector("[data-empty]"); if (empty) empty.remove();
      // Oldest first in the batch: inserting each at the top leaves the newest on top.
      rows.forEach(function (r) { rBody.insertBefore(rRow(r), rBody.firstChild); });
      while (rBody.children.length > rMax) rBody.removeChild(rBody.lastChild);
    });
  }

  window.peephole = window.peephole || {};
  window.peephole.ago = ago;
})();
