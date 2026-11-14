// Runs before first paint: enables JS-only styles (tabs) and restores the
// theme without a visible flash. No inline scripts (CSP).
(function () {
  "use strict";
  var d = document.documentElement;
  d.classList.add("js");
  // Theme: light, dark or auto (follows the system); remembered per browser.
  try { var t = window.localStorage.getItem("ndo4.theme"); d.setAttribute("data-theme", t === "light" || t === "auto" ? t : "dark"); } catch (e) { d.setAttribute("data-theme", "dark"); }
  // Keep several open tabs/pages on the same theme: a change made in one shows in the others at once.
  window.addEventListener("storage", function (e) {
    if (e.key !== "ndo4.theme") return;
    var v = e.newValue === "light" || e.newValue === "auto" ? e.newValue : "dark";
    d.setAttribute("data-theme", v);
    var cur = v;
    var bs = document.querySelectorAll(".js-theme");
    for (var i = 0; i < bs.length; i++) bs[i].classList.toggle("on", bs[i].getAttribute("data-theme") === cur);
  });
})();
