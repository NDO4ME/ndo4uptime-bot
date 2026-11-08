// Runs before first paint: enables JS-only styles (tabs) and restores the
// theme without a visible flash. No inline scripts (CSP).
(function () {
  "use strict";
  var d = document.documentElement;
  d.classList.add("js");
  // Theme: light, dark or auto (follows the system); remembered per browser.
  try { var t = window.localStorage.getItem("ndo4.theme"); d.setAttribute("data-theme", t === "light" || t === "auto" ? t : "dark"); } catch (e) { d.setAttribute("data-theme", "dark"); }
})();
