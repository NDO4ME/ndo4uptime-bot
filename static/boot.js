// Runs before first paint: enables JS-only styles (tabs) and restores the
// collapsed sidebar without a visible jump. No inline scripts (CSP).
(function () {
  "use strict";
  var d = document.documentElement;
  d.classList.add("js");
  try { if (window.localStorage.getItem("ndo4.sidebar") === "mini") d.classList.add("sb-mini"); } catch (e) { /* storage blocked */ }
})();
