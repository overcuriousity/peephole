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
  // One-shot notice the server set after an action; shown once, then cleared.
  var fm = document.cookie.match(/(?:^|; )peephole_flash=([^;]*)/);
  if (fm) {
    document.cookie = "peephole_flash=; Path=/; Max-Age=0; SameSite=Strict";
    var main = document.querySelector("main");
    if (main) {
      var note = document.createElement("div");
      note.className = "banner banner-success";
      try { note.textContent = decodeURIComponent(fm[1].replace(/\+/g, " ")); } catch (e) { note.textContent = ""; }
      if (note.textContent) main.insertBefore(note, main.firstChild);
    }
  }
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
      tr.appendChild(cell("mono", esc(j.error)));
      tr.appendChild(cell("muted", esc(j.scanner) + (j.arbiter ? '<span class="node-via"> via ' + esc(j.arbiter) + "</span>" : "")));
      return tr;
    };
    // The page's status/level filter applies to live rows too.
    var fStatus = qt.getAttribute("data-filter-status") || "", fLevel = qt.getAttribute("data-filter-level") || "";
    var matches = function (j) { return (!fStatus || j.status === fStatus) && (!fLevel || String(j.level) === fLevel); };
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

  window.peephole = window.peephole || {};
})();
