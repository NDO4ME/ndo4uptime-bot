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

  var WATCH = ".vital-v, td.num, .badge, .hbar";
  function sig(el) {
    if (el.classList.contains("hbar")) {
      return Array.prototype.map.call(el.children, function (c) { return c.className; }).join(",");
    }
    return el.textContent;
  }
  function snap() {
    return Array.prototype.map.call(live.querySelectorAll(WATCH), sig);
  }
  var tickTimer = 0;
  /* Compare with the previous frame: sweep the top line, glow what changed, slide in new beats. */
  function announce(before) {
    var els = live.querySelectorAll(WATCH), changed = [];
    if (els.length === before.length) {
      Array.prototype.forEach.call(els, function (el, i) {
        if (sig(el) === before[i]) return;
        el.classList.add(el.classList.contains("hbar") ? "fresh" : "flash");
        changed.push(el);
      });
    }
    doc.body.classList.remove("tick");
    void doc.body.offsetWidth;
    doc.body.classList.add("tick");
    clearTimeout(tickTimer);
    tickTimer = setTimeout(function () {
      doc.body.classList.remove("tick");
      changed.forEach(function (el) { el.classList.remove("flash", "fresh"); });
    }, 1500);
  }
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
      if (live.innerHTML === html) return;
      var before = snap();
      live.innerHTML = html;
      announce(before);
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

/* Localise <time data-ts> (status pages and maintenance notices) to the visitor's timezone. */
(function () {
  try {
    var fmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    var run = function () {
      document.querySelectorAll('time[data-ts]').forEach(function (t) {
        var s = +t.getAttribute('data-ts');
        if (s > 0) { var v = fmt.format(new Date(s * 1000)); if (t.textContent !== v) t.textContent = v; }
      });
    };
    run();
    var live = document.getElementById('live');
    if (live) new MutationObserver(run).observe(live, { childList: true, subtree: true });
  } catch (e) { /* keep the UTC text */ }
})();

/* Dashboard filter: search + status segments. Re-applied after every live update. */
(function () {
  var bar = document.getElementById('mon-filter'), live = document.getElementById('live');
  if (!bar || !live) return;
  var q = document.getElementById('mon-q'), f = 'all';
  try { f = sessionStorage.getItem('ndo4.f') || 'all'; q.value = sessionStorage.getItem('ndo4.q') || ''; } catch (e) {}
  var segs = bar.querySelectorAll('.seg-b');
  function apply() {
    var term = q.value.trim().toLowerCase(), shown = 0, grp = null, grpShown = 0;
    var rows = live.querySelectorAll('table.tbl tbody tr');
    function closeGrp() { if (grp) grp.hidden = grpShown === 0; }
    rows.forEach(function (r) {
      if (r.classList.contains('grp-row')) { closeGrp(); grp = r; grpShown = 0; return; }
      if (r.classList.contains('no-match')) return;
      var st = r.getAttribute('data-state') || '';
      var okS = f === 'all' || st === f;
      var okQ = !term || (r.getAttribute('data-name') || '').indexOf(term) > -1;
      r.hidden = !(okS && okQ);
      if (!r.hidden) { shown++; grpShown++; }
    });
    closeGrp();
    var tb = live.querySelector('table.tbl tbody');
    if (tb && rows.length) {
      var nm = tb.querySelector('.no-match');
      if (!shown && !nm) { nm = document.createElement('tr'); nm.className = 'no-match'; nm.innerHTML = '<td colspan="7">No monitors match the filter.</td>'; tb.appendChild(nm); }
      else if (shown && nm) nm.remove();
    }
  }
  segs.forEach(function (b) {
    b.classList.toggle('on', b.getAttribute('data-f') === f);
    b.addEventListener('click', function () {
      f = b.getAttribute('data-f');
      segs.forEach(function (x) { x.classList.toggle('on', x === b); });
      try { sessionStorage.setItem('ndo4.f', f); } catch (e) {}
      apply();
    });
  });
  q.addEventListener('input', function () { try { sessionStorage.setItem('ndo4.q', q.value); } catch (e) {} apply(); });
  new MutationObserver(apply).observe(live, { childList: true });
  apply();
})();
