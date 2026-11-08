// Admin-only behaviour: theme switch, notification type panes, display time zone.
(function () {
  "use strict";
  var root = document.documentElement;

  /* theme */
  function mark() {
    var cur = root.getAttribute("data-theme") || "dark";
    document.querySelectorAll(".js-theme").forEach(function (b) { b.classList.toggle("on", b.getAttribute("data-theme") === cur); });
  }
  document.addEventListener("click", function (ev) {
    var b = ev.target.closest ? ev.target.closest(".js-theme") : null;
    if (b) {
      var t = b.getAttribute("data-theme");
      root.setAttribute("data-theme", t);
      try { localStorage.setItem("ndo4.theme", t); } catch (e) {}
      mark();
      return;
    }
    document.querySelectorAll("details.menu[open]").forEach(function (d) { if (!d.contains(ev.target)) d.removeAttribute("open"); });
  });
  mark();

  /* notification type: show only the fields of the chosen type */
  var sel = document.getElementById("nk");
  if (sel) {
    var panes = document.querySelectorAll(".nk-pane");
    var apply = function () {
      panes.forEach(function (p) {
        var on = p.getAttribute("data-kind") === sel.value;
        p.hidden = !on;
        p.querySelectorAll("input,select,textarea").forEach(function (i) { i.disabled = !on; });
      });
    };
    sel.addEventListener("change", apply);
    apply();
  }

  /* times are sent as UTC; show them in the configured zone */
  var tz = document.documentElement.getAttribute("data-tz") || "";
  var h12 = document.documentElement.getAttribute("data-h12") === "1";
  function fmt(root2) {
    (root2 || document).querySelectorAll("time[data-ts]").forEach(function (el) {
      var ts = parseInt(el.getAttribute("data-ts"), 10);
      if (!ts || el.getAttribute("data-done") === ts + tz) return;
      try {
        var o = { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: h12 };
        if (tz) o.timeZone = tz;
        var p = {};
        new Intl.DateTimeFormat("en-CA", o).formatToParts(new Date(ts * 1000)).forEach(function (x) { p[x.type] = x.value; });
        el.textContent = p.year + "-" + p.month + "-" + p.day + " " + p.hour + ":" + p.minute + ":" + p.second + (h12 && p.dayPeriod ? " " + p.dayPeriod : "");
        el.title = tz || "browser time zone";
        el.setAttribute("data-done", ts + tz);
      } catch (e) {}
    });
  }
  fmt();
  new MutationObserver(function () { fmt(); }).observe(document.body, { childList: true, subtree: true });

  /* settings: one section at a time (all stay visible without JavaScript) */
  var tabs = document.querySelector(".stabs");
  if (tabs && document.querySelector(".sg[id]")) {
    var groups = document.querySelectorAll(".sg[id]");
    var show = function (id) {
      groups.forEach(function (g) { g.classList.toggle("off", g.id !== id); });
      tabs.querySelectorAll("a").forEach(function (a) { a.classList.toggle("on", a.getAttribute("href") === "#" + id); });
    };
    var start = (location.hash || "").slice(1);
    if (!document.getElementById(start) || start.indexOf("sg-") !== 0) {
      var bad = document.querySelector(".sg .msg-err");
      start = bad ? bad.closest(".sg").id : "sg-general";
    }
    show(start);
    tabs.addEventListener("click", function (ev) {
      var a = ev.target.closest("a");
      if (!a || a.getAttribute("href").charAt(0) !== "#") return;
      ev.preventDefault();
      var id = a.getAttribute("href").slice(1);
      show(id);
      try { history.replaceState(null, "", "#" + id); } catch (e) {}
    });
  }

  /* time zone list for the settings page */
  var dl = document.getElementById("tz-list");
  if (dl && Intl.supportedValuesOf) {
    Intl.supportedValuesOf("timeZone").forEach(function (z) { var o = document.createElement("option"); o.value = z; dl.appendChild(o); });
  }
})();
