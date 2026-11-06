(function () {
  "use strict";
  var doc = document;

  /* ---------- monitor form: show fields per check type ---------- */
  var kind = doc.getElementById("f-kind");
  if (kind) {
    var sync = function () {
      var k = kind.value;
      doc.querySelectorAll("[data-for]").forEach(function (el) {
        el.classList.toggle("hide", el.getAttribute("data-for").split(" ").indexOf(k) === -1);
      });
    };
    kind.addEventListener("change", sync);
    sync();
  }

  /* ---------- live stream: server-sent events swap the view in place ---------- */
  var live = doc.getElementById("live");
  if (!live || !window.EventSource) return;
  var url = live.getAttribute("data-live"), pill = doc.getElementById("live-pill"),
      conn = doc.getElementById("conn"), es = null, retry = 0, timer = 0;

  function state(on) {
    if (pill) pill.classList.toggle("on", on);
    if (conn) conn.classList.toggle("on", !on);
  }
  function close() { if (es) { es.close(); es = null; } clearTimeout(timer); }
  function open() {
    close();
    es = new EventSource(url);
    es.onopen = function () { retry = 0; state(true); };
    es.addEventListener("frag", function (e) {
      state(true);
      var html; try { html = JSON.parse(e.data); } catch (_) { return; }
      if (live.innerHTML !== html) live.innerHTML = html;
    });
    es.addEventListener("gone", function () { if (live.hasAttribute("data-public")) location.reload(); else location.href = "/"; });
    es.addEventListener("auth", function () { location.reload(); });
    es.onerror = function () {
      state(false);
      if (es && es.readyState === 2) {          // closed for good: session gone or server refused
        close();
        timer = setTimeout(function () {
          fetch("/healthz", { credentials: "same-origin" }).then(function () {
            return fetch(location.pathname, { credentials: "same-origin", redirect: "manual" });
          }).then(function (r) {
            if (r.type === "opaqueredirect") location.reload(); else open();
          }, open);
        }, Math.min(15000, 1000 * Math.pow(2, retry++)));
      }
    };
  }
  doc.addEventListener("visibilitychange", function () {
    if (doc.visibilityState === "visible") open(); else close();
  });
  window.addEventListener("pagehide", close);
  open();
})();
