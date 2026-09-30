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
  window.peephole = window.peephole || {};
})();
