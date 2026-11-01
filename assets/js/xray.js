// Body X-ray: elements sharing a data-l value light up together on hover and
// focus, and the hex button swaps the original bytes for a dump. The page
// reads without this script.
(function () {
  "use strict";
  var all = Array.prototype.slice.call(document.querySelectorAll("#xray [data-l]"));
  var byKey = {};
  all.forEach(function (e) {
    var k = e.getAttribute("data-l");
    (byKey[k] = byKey[k] || []).push(e);
  });
  function mark(e, on) {
    (byKey[e.getAttribute("data-l")] || []).forEach(function (x) { x.classList.toggle("hot", on); });
  }
  all.forEach(function (e) {
    e.addEventListener("mouseenter", function () { mark(e, true); });
    e.addEventListener("mouseleave", function () { mark(e, false); });
    e.addEventListener("focus", function () { mark(e, true); });
    e.addEventListener("blur", function () { mark(e, false); });
  });

  var btn = document.querySelector("[data-xray-hex]");
  var raw = document.getElementById("xr-raw");
  var hex = document.getElementById("xr-hex");
  if (!btn || !raw || !hex) return;
  var built = false;
  btn.addEventListener("click", function () {
    var on = hex.hidden;
    if (on && !built) {
      var bin = atob(hex.getAttribute("data-b64") || "");
      var lines = [];
      for (var i = 0; i < bin.length; i += 16) {
        var row = [], txt = "";
        for (var j = i; j < Math.min(i + 16, bin.length); j++) {
          var c = bin.charCodeAt(j);
          row.push(c.toString(16).padStart(2, "0"));
          txt += c >= 32 && c < 127 ? bin.charAt(j) : ".";
        }
        lines.push(i.toString(16).padStart(8, "0") + "  " + row.join(" ").padEnd(48) + "  " + txt);
      }
      hex.textContent = lines.join("\n");
      built = true;
    }
    hex.hidden = !on;
    raw.hidden = on;
    btn.textContent = on ? "text" : "hex";
  });
})();
