// NDO4Panel UI. Progressive enhancement only: every action is a plain form
// that also works without this file. No inline scripts (CSP script-src 'self').
(function () {
  "use strict";

  var doc = document, root = doc.documentElement;
  var meta = doc.querySelector('meta[name="csrf-token"]');
  var csrf = meta ? meta.getAttribute("content") : "";
  var SPRITE = "/static/icons.svg#";

  function $(sel, ctx) { return (ctx || doc).querySelector(sel); }
  function $$(sel, ctx) { return Array.prototype.slice.call((ctx || doc).querySelectorAll(sel)); }
  function store(key, val) {
    try {
      if (val === undefined) return window.localStorage.getItem(key);
      if (val === null) window.localStorage.removeItem(key); else window.localStorage.setItem(key, val);
    } catch (e) { /* storage unavailable */ }
    return null;
  }
  function icon(name, cls) {
    var ns = "http://www.w3.org/2000/svg";
    var s = doc.createElementNS(ns, "svg"), u = doc.createElementNS(ns, "use");
    s.setAttribute("class", "ic" + (cls ? " " + cls : "")); s.setAttribute("aria-hidden", "true");
    u.setAttribute("href", SPRITE + name); s.appendChild(u);
    return s;
  }
  function el(tag, attrs, kids) {
    var e = doc.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") e.textContent = attrs[k]; else e.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c) e.appendChild(c); });
    return e;
  }

  // One failing feature must never take the rest of the page down.
  function guard(name, fn) {
    try { return fn(); } catch (e) { if (window.console) console.error("[ndo4] " + name + ":", e); }
  }

  doc.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") $$("details.menu[open]").forEach(function (d) { d.removeAttribute("open"); });
  });
  // Close popup menus on outside click.
  doc.addEventListener("click", function (ev) {
    $$("details.menu[open]").forEach(function (d) { if (!d.contains(ev.target)) d.removeAttribute("open"); });
  });

  /* ---------- tabs ---------- */
  function activate(tabs, id, push) {
    var found = false;
    $$(".tab", tabs).forEach(function (a) {
      var on = a.getAttribute("href") === "#" + id;
      a.setAttribute("aria-selected", on ? "true" : "false");
      a.setAttribute("tabindex", on ? "0" : "-1");
      found = found || on;
    });
    if (!found) return false;
    $$(":scope > .tabpanel", tabs).forEach(function (p) { p.classList.toggle("is-active", p.id === id); });
    store("ndo4.tab:" + location.pathname, id);
    if (push && history.replaceState) history.replaceState(null, "", "#" + id);
    return true;
  }
  $$("[data-tabs]").forEach(function (tabs) {
    var list = $(".tablist", tabs);
    if (!list) return;
    list.addEventListener("click", function (ev) {
      var a = ev.target.closest(".tab");
      if (!a) return;
      ev.preventDefault();
      activate(tabs, a.getAttribute("href").slice(1), true);
    });
    list.addEventListener("keydown", function (ev) {
      if (ev.key !== "ArrowRight" && ev.key !== "ArrowLeft") return;
      var all = $$(".tab", list), i = all.indexOf(doc.activeElement);
      if (i < 0) return;
      var n = all[(i + (ev.key === "ArrowRight" ? 1 : all.length - 1)) % all.length];
      n.focus(); n.click();
    });
    // Pick the initial tab: URL fragment (also anchors inside a tab) >
    // a panel that carries a one-time secret or fresh output > last used.
    var pick = null, h = location.hash.slice(1), target = h ? doc.getElementById(h) : null;
    if (target) {
      var p = target.classList.contains("tabpanel") ? target : target.closest(".tabpanel");
      if (p && tabs.contains(p)) pick = p.id;
    }
    if (!pick) {
      var hot = $(".tabpanel .secret, .tabpanel [data-tab-focus], .tabpanel .msg-err", tabs);
      if (hot) pick = hot.closest(".tabpanel").id;
    }
    if (!pick) pick = store("ndo4.tab:" + location.pathname);
    if (!pick || !activate(tabs, pick, false)) {
      var first = $(".tab", list);
      if (first) activate(tabs, first.getAttribute("href").slice(1), false);
    }
    if (target && target !== tabs && !target.classList.contains("tabpanel")) {
      setTimeout(function () { target.scrollIntoView({ block: "start" }); }, 0);
    }
    // In-page links such as /deploy#tab-releases from the same page.
    window.addEventListener("hashchange", function () {
      var t = doc.getElementById(location.hash.slice(1));
      var p = t && (t.classList.contains("tabpanel") ? t : t.closest(".tabpanel"));
      if (p && tabs.contains(p)) activate(tabs, p.id, false);
    });
  });

  /* ---------- modal confirmation ---------- */
  // modal(opts) resolves to {ok, value, token}.
  // opts: title, text, okText, danger, expect (typed value), input (prompt
  // default), inputLabel, reauth (ask for the panel token).
  var dlg = null;
  function modal(opts) {
    return new Promise(function (resolve) {
      if (!window.HTMLDialogElement) {
        if (opts.expect) return resolve({ ok: window.prompt(opts.text + "\n\nType \"" + opts.expect + "\" to confirm:") === opts.expect });
        if (opts.input !== undefined) { var v = window.prompt(opts.text, opts.input); return resolve({ ok: v !== null, value: v }); }
        return resolve({ ok: window.confirm(opts.text) });
      }
      if (dlg) dlg.remove();
      var field = null, token = null;
      var ok = el("button", { type: "submit", value: "ok", "class": "btn " + (opts.danger ? "btn-danger-solid" : "btn-primary"), text: opts.okText || "Confirm" });
      var cancel = el("button", { type: "button", "class": "btn", text: "Cancel" });
      var body = el("div", { "class": "modal-b" }, [doc.createTextNode(opts.text || "")]);
      if (opts.expect !== undefined || opts.input !== undefined) {
        field = el("input", { type: "text", autocomplete: "off", spellcheck: "false" });
        if (opts.input !== undefined) field.value = opts.input;
        body.appendChild(el("label", { "class": "field" }, [
          el("span", { "class": "lbl", text: opts.expect !== undefined ? "Type “" + opts.expect + "” to confirm" : (opts.inputLabel || "Value") }), field]));
      }
      if (opts.reauth) {
        token = el("input", { type: "password", autocomplete: "off", required: "required" });
        body.appendChild(el("label", { "class": "field reauth" }, [
          el("span", { "class": "lbl", text: "Panel token — your last sign-in is older than 5 minutes" }), token]));
      }
      var form = el("form", { method: "dialog" }, [
        el("div", { "class": "modal-h" + (opts.danger ? " danger" : "") }, [icon(opts.danger ? "alert" : "help"), el("h2", { text: opts.title || "Confirm action" })]),
        body,
        el("div", { "class": "modal-f" }, [cancel, ok])
      ]);
      dlg = el("dialog", { "class": "modal" }, [form]);
      doc.body.appendChild(dlg);
      function check() {
        var good = true;
        if (opts.expect !== undefined) good = field.value === opts.expect;
        if (token) good = good && token.value.length > 0;
        ok.disabled = !good;
      }
      if (field) field.addEventListener("input", check);
      if (token) token.addEventListener("input", check);
      check();
      cancel.addEventListener("click", function () { dlg.close("cancel"); });
      dlg.addEventListener("close", function () {
        var res = { ok: dlg.returnValue === "ok", value: field ? field.value : undefined, token: token ? token.value : undefined };
        dlg.remove(); dlg = null;
        resolve(res);
      });
      dlg.showModal();
      (field || token || ok).focus();
      if (field && opts.input !== undefined) field.select();
    });
  }

  // The modal collects the panel token, so the field in a confirm form is
  // hidden by CSS and must not take part in constraint validation: a hidden
  // required control makes the browser cancel the submit ("not focusable")
  // before the submit handler below ever runs. Without JavaScript the field
  // stays visible and required.
  $$("form.js-confirm input[name=reauth_token]").forEach(function (i) { i.removeAttribute("required"); });

  doc.addEventListener("submit", function (ev) {
    var f = ev.target;
    if (!f.classList || !f.classList.contains("js-confirm") || f.dataset.confirmed === "1") return;
    ev.preventDefault();
    var submitter = ev.submitter || null;
    var danger = !!$(".btn-danger, .btn.danger", f) || f.hasAttribute("data-confirm-value");
    var label = submitter && (submitter.textContent.trim() || submitter.getAttribute("title"));
    var ra = $("input[name=reauth_token]", f);
    modal({
      title: f.getAttribute("data-confirm-title") || label || "Confirm action",
      text: f.getAttribute("data-confirm") || "Are you sure?",
      okText: label || "Confirm",
      danger: danger,
      expect: f.getAttribute("data-confirm-value") || undefined,
      reauth: !!ra && !ra.value
    }).then(function (r) {
      if (!r.ok) return;
      if (ra && r.token !== undefined) ra.value = r.token;
      f.dataset.confirmed = "1";
      if (f.requestSubmit) f.requestSubmit(submitter || undefined); else f.submit();
      delete f.dataset.confirmed;
    });
  });

  // Busy state on submit (prevents double posts of long operations).
  doc.addEventListener("submit", function (ev) {
    var f = ev.target;
    if (ev.defaultPrevented || f.method === "get" || f.getAttribute("method") === "dialog" || f.target === "_blank") return;
    var b = ev.submitter || $("button[type=submit], button:not([type])", f);
    if (b) setTimeout(function () { b.classList.add("is-busy"); }, 0);
  });
  window.addEventListener("pageshow", function () { $$(".is-busy").forEach(function (b) { b.classList.remove("is-busy"); }); });

  /* ---------- rename (files) ---------- */
  doc.addEventListener("click", function (ev) {
    var b = ev.target.closest ? ev.target.closest(".js-rename") : null;
    if (!b) return;
    var f = b.closest("form"), input = f && $("input[name=name]", f);
    if (!input) return;
    ev.preventDefault();
    modal({ title: "Rename", text: "New name for " + input.value, input: input.value, inputLabel: "Name", okText: "Rename" })
      .then(function (r) {
        if (!r.ok || !r.value || r.value === input.value) return;
        input.value = r.value;
        f.submit();
      });
  });

  /* ---------- filter: input[data-filter="<css selector of rows>"] ---------- */
  doc.addEventListener("input", function (ev) {
    var i = ev.target;
    if (!i.matches || !i.matches("input[data-filter]")) return;
    var q = i.value.trim().toLowerCase();
    $$(i.getAttribute("data-filter")).forEach(function (row) {
      row.hidden = q !== "" && row.textContent.toLowerCase().indexOf(q) < 0;
    });
  });

  /* ---------- follow a background run ---------- */
  var follow = doc.querySelector("[data-autorefresh]");
  if (follow && follow.id) {
    /* A panel with an id is refreshed in place: no page reload, so typed text, scroll position and
       open tabs stay. While the visitor is typing in it (or the tab is hidden) the swap waits. */
    var every = parseInt(follow.getAttribute("data-autorefresh"), 10) || 3000, fid = follow.id, busy = false;
    var poll = function () {
      var cur = doc.getElementById(fid);
      if (!cur) return;
      var a = doc.activeElement, typing = a && cur.contains(a) && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName);
      var filled = Array.prototype.some.call(cur.querySelectorAll("input[type=password],input[type=text]"), function (i) { return i.value !== i.defaultValue; });
      if (doc.hidden || typing || filled || busy) { setTimeout(poll, every); return; }
      busy = true;
      fetch(location.href, { credentials: "same-origin", headers: { "X-Requested-With": "fetch" } })
        .then(function (r) { if (!r.ok || r.redirected && /\/login/.test(r.url)) throw 0; return r.text(); })
        .then(function (html) {
          var fresh = new DOMParser().parseFromString(html, "text/html").getElementById(fid);
          var now = doc.getElementById(fid);
          if (!fresh || !now) throw 0;
          var a2 = doc.activeElement;
          if (!(a2 && now.contains(a2) && /^(INPUT|TEXTAREA|SELECT)$/.test(a2.tagName))) now.replaceWith(fresh);
          busy = false;
          if (fresh.hasAttribute("data-autorefresh")) setTimeout(poll, every);
        })
        .catch(function () { busy = false; setTimeout(poll, every * 2); });
    };
    setTimeout(poll, every);
  } else if (follow) {
    setTimeout(function () { location.reload(); }, parseInt(follow.getAttribute("data-autorefresh"), 10) || 3000);
  }

  /* ---------- copy, dismiss, back ---------- */
  var toastEl = null, toastTimer = 0;
  function toast(text, kind) {
    if (!toastEl) { toastEl = el("div", { "class": "toast", role: "status", "aria-live": "polite" }); doc.body.appendChild(toastEl); }
    toastEl.textContent = ""; toastEl.className = "toast" + (kind ? " " + kind : "");
    toastEl.appendChild(icon(kind === "err" ? "x-circle" : kind === "warn" ? "alert" : "check")); toastEl.appendChild(doc.createTextNode(text));
    toastEl.classList.add("on");
    clearTimeout(toastTimer); toastTimer = setTimeout(function () { toastEl.classList.remove("on"); }, 1600);
  }
  doc.addEventListener("click", function (ev) {
    var t = ev.target.closest ? ev.target.closest(".js-copy, .js-dismiss, .js-back") : null;
    if (!t) return;
    if (t.classList.contains("js-copy")) {
      var text = t.getAttribute("data-copy-text");
      if (text === null) {
        var src = doc.getElementById(t.getAttribute("data-copy"));
        if (!src) return;
        text = (src.value !== undefined && src.tagName !== "SPAN" && src.tagName !== "CODE" ? src.value : src.textContent).trim();
      }
      var done = function () { toast("Copied to clipboard"); };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
      } else { fallbackCopy(text); done(); }
    } else if (t.classList.contains("js-dismiss")) {
      var m = t.closest(".msg"); if (m) m.remove();
    } else if (t.classList.contains("js-back") && history.length > 1) {
      ev.preventDefault(); history.back();
    }
  });
  function fallbackCopy(text) {
    var ta = el("textarea", { "class": "sr-only" }); ta.value = text; doc.body.appendChild(ta); ta.select();
    try { doc.execCommand("copy"); } catch (e) { /* ignore */ }
    ta.remove();
  }

  /* ---------- bars ---------- */
  function setBar(bar, pct) {
    if (!bar) return;
    pct = Math.max(0, Math.min(100, pct || 0));
    var i = bar.firstElementChild || bar.appendChild(doc.createElement("i"));
    i.style.width = pct.toFixed(1) + "%";
    bar.classList.toggle("warn", pct >= 75 && pct < 90);
    bar.classList.toggle("crit", pct >= 90);
  }
  $$(".bar[data-pct]").forEach(function (b) { setBar(b, parseFloat(b.getAttribute("data-pct"))); });

  /* ---------- data helpers ---------- */
  // Connection state: two failed requests in a row show "Reconnecting…" in
  // the top bar; the next success hides it again.
  var conn = $("#conn"), connFails = 0;
  function connState(ok) {
    connFails = ok ? 0 : connFails + 1;
    if (conn) conn.classList.toggle("on", connFails >= 2);
  }
  function getJSON(url, timeoutMs) {
    var ctl = window.AbortController ? new AbortController() : null;
    var timer = ctl ? setTimeout(function () { ctl.abort(); }, timeoutMs || 10000) : 0;
    return fetch(url, { credentials: "same-origin", signal: ctl ? ctl.signal : undefined,
        headers: { "Accept": "application/json", "X-CSRF-Token": csrf } })
      .then(function (r) {
        clearTimeout(timer);
        if (r.status === 401) { location.href = "/login"; throw new Error("auth"); }
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (d) { connState(true); return d; }, function (e) {
        clearTimeout(timer);
        if (!e || e.message !== "auth") connState(false);
        throw e;
      });
  }
  // poll runs fn every ms while the tab is visible: one request at a time
  // (a slow server never gets a pile-up), exponential backoff up to 30 s
  // after failures, an immediate refresh when the tab returns or the
  // network comes back. fn returns a promise; a rejection counts as failure.
  function poll(fn, ms) {
    var timer = 0, running = true, delay = ms, busy = false;
    function schedule() {
      if (running && !timer && doc.visibilityState === "visible") timer = setTimeout(tick, delay + Math.round(Math.random() * 150));
    }
    function tick() {
      timer = 0;
      if (!running || doc.visibilityState !== "visible") return;
      if (busy) { schedule(); return; }
      busy = true;
      var done = function (ok) { busy = false; delay = ok ? ms : Math.min(delay * 2, 30000); schedule(); };
      var p;
      try { p = fn(); } catch (e) { done(false); return; }
      if (p && p.then) p.then(function () { done(true); }, function () { done(false); }); else done(true);
    }
    function now() { clearTimeout(timer); timer = 0; delay = ms; tick(); }
    doc.addEventListener("visibilitychange", function () {
      if (doc.visibilityState === "visible") now(); else { clearTimeout(timer); timer = 0; }
    });
    window.addEventListener("online", now);
    schedule();
    return function stop() { running = false; clearTimeout(timer); timer = 0; };
  }
  function fmtBytes(n) {
    var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n.toFixed(0)) + " " + u[i];
  }
  function fmtUptime(s) {
    s = Math.floor(s);
    var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return d ? d + "d " + h + "h" : h ? h + "h " + m + "m" : m + "m";
  }
  function cssVar(name, fb) { var v = getComputedStyle(root).getPropertyValue(name).trim(); return v || fb; }

  guard("vitals", function () {
    /* ---------- vitals: trend charts ---------- */
    // A trace of the last two minutes. It is drawn once per sample (every few
    // seconds) and on resize, never in an animation loop, so an open dashboard
    // costs next to nothing.
    var TONES = { ok: ["--primary", "#37cf0f"], warn: ["--warn", "#e0a32e"], crit: ["--err", "#e2554d"] };
    function Pulse(canvas, cfg) {
      var ctx = canvas.getContext && canvas.getContext("2d");
      if (!ctx) return null;
      var windowMs = 120000, pts = [], tone = "ok";
      function fit() {
        var dpr = window.devicePixelRatio || 1, w = canvas.clientWidth, h = canvas.clientHeight;
        if (!w || !h) return null;
        var pw = Math.round(w * dpr), ph = Math.round(h * dpr);
        if (canvas.width !== pw || canvas.height !== ph) { canvas.width = pw; canvas.height = ph; }
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        return [w, h];
      }
      function rgba(hex, a) {
        var n = parseInt(hex.slice(1), 16);
        return "rgba(" + (n >> 16) + "," + (n >> 8 & 255) + "," + (n & 255) + "," + a + ")";
      }
      return {
        push: function (v) {
          var now = Date.now();
          pts.push([now, v]);
          while (pts.length > 90 || (pts.length > 2 && pts[1][0] < now - windowMs - 4000)) pts.shift();
          tone = cfg.tone(v);
        },
        peak: function () { return pts.reduce(function (m, p) { return Math.max(m, p[1]); }, 0); },
        draw: function (now) {
          var sz = fit(); if (!sz || !pts.length) return;
          var w = sz[0], h = sz[1], pad = 7, max = cfg.max(this), self = this;
          var tv = TONES[tone], col = cssVar(tv[0], tv[1]);
          if (col.charAt(0) !== "#") col = tv[1];
          ctx.clearRect(0, 0, w, h);
          var X = function (t) { return w - (now - t) / windowMs * w; };
          var Y = function (v) { return h - pad - Math.max(0, Math.min(v / max, 1)) * (h - pad * 2); };
          // grid: horizontal quarters and a vertical line every 30 s that scrolls with the trace
          ctx.lineWidth = 1; ctx.strokeStyle = "rgba(255,255,255,.055)"; ctx.beginPath();
          for (var q = 1; q < 4; q++) { var gy = Math.round(h * q / 4) + .5; ctx.moveTo(0, gy); ctx.lineTo(w, gy); }
          for (var gt = Math.floor(now / 30000) * 30000; X(gt) > 0; gt -= 30000) { var gx = Math.round(X(gt)) + .5; ctx.moveTo(gx, 0); ctx.lineTo(gx, h); }
          ctx.stroke();
          if (cfg.ref) {
            var ry = Math.round(Y(cfg.ref())) + .5;
            ctx.setLineDash([4, 4]); ctx.strokeStyle = "rgba(255,255,255,.22)"; ctx.beginPath(); ctx.moveTo(0, ry); ctx.lineTo(w, ry); ctx.stroke(); ctx.setLineDash([]);
          }
          // trace points: a flat lead-in from the left edge, the samples, a flat lead-out to now
          var xy = [[0, Y(pts[0][1])]];
          pts.forEach(function (p) { xy.push([Math.max(0, X(p[0])), Y(p[1])]); });
          xy.push([w, Y(pts[pts.length - 1][1])]);
          var trace = function () {
            ctx.beginPath(); ctx.moveTo(xy[0][0], xy[0][1]);
            for (var i = 1; i < xy.length - 1; i++) {
              var mx = (xy[i][0] + xy[i + 1][0]) / 2, my = (xy[i][1] + xy[i + 1][1]) / 2;
              ctx.quadraticCurveTo(xy[i][0], xy[i][1], mx, my);
            }
            ctx.lineTo(xy[xy.length - 1][0], xy[xy.length - 1][1]);
          };
          trace(); ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
          var g = ctx.createLinearGradient(0, 0, 0, h); g.addColorStop(0, rgba(col, .30)); g.addColorStop(1, rgba(col, 0));
          ctx.fillStyle = g; ctx.fill();
          trace(); ctx.lineWidth = 2; ctx.lineJoin = "round"; ctx.lineCap = "round"; ctx.strokeStyle = col;
          ctx.stroke();
          // current value: a dot with a soft halo
          var ex = w - 4, ey = xy[xy.length - 1][1];
          ctx.beginPath(); ctx.arc(ex, ey, 6, 0, Math.PI * 2); ctx.fillStyle = rgba(col, .18); ctx.fill();
          ctx.beginPath(); ctx.arc(ex, ey, 3, 0, Math.PI * 2); ctx.fillStyle = col; ctx.fill();
        }
      };
    }

    /* ---------- dashboard vitals ---------- */
    if ($("#m-cpu")) {
      var vitals = $(".vitals"), cores = parseInt(vitals && vitals.getAttribute("data-cores"), 10) || 1;
      var level = function (pct) { return pct >= 90 ? "crit" : pct >= 70 ? "warn" : "ok"; };
      var charts = {
        cpu: Pulse($("canvas[data-pulse=cpu]"), { max: function () { return 100; }, tone: level }),
        mem: Pulse($("canvas[data-pulse=mem]"), { max: function () { return 100; }, tone: function (v) { return v >= 90 ? "crit" : v >= 75 ? "warn" : "ok"; } }),
        load: Pulse($("canvas[data-pulse=load]"), {
          max: function (p) { return Math.max(cores * 1.25, p.peak() * 1.15, 1); },
          ref: function () { return cores; },
          tone: function (v) { var r = v / cores; return r >= 1.5 ? "crit" : r >= 1 ? "warn" : "ok"; }
        })
      };
      var tint = function (canvasKey, t) {
        var c = $("canvas[data-pulse=" + canvasKey + "]"), v = c && c.closest(".vital");
        if (v) { v.classList.toggle("warn", t === "warn"); v.classList.toggle("crit", t === "crit"); }
      };
      var set = function (id, v) { var e = doc.getElementById(id); if (e && e.textContent !== v) e.textContent = v; };
      var paint = function (d) {
        var m = d.latest; if (!m) return;
        var memPct = m.memt ? m.mem / m.memt * 100 : 0, diskPct = m.diskt ? m.disk / m.diskt * 100 : 0;
        set("m-cpu", m.cpu.toFixed(0));
        set("m-mem", fmtBytes(m.mem)); set("m-memt", "of " + fmtBytes(m.memt)); set("m-mem-p", memPct.toFixed(0));
        set("m-swap", m.swapt ? "swap " + fmtBytes(m.swap) + " / " + fmtBytes(m.swapt) : "no swap");
        set("m-load", m.load1.toFixed(2)); set("m-load-s", "5m " + m.load5.toFixed(2) + " · 15m " + m.load15.toFixed(2));
        set("m-up", fmtUptime(m.uptime));
        set("m-disk", fmtBytes(m.disk)); set("m-diskt", fmtBytes(m.diskt)); set("m-disk-free", fmtBytes(Math.max(0, m.diskt - m.disk)));
        set("m-disk-p", diskPct.toFixed(0));
        var ring = doc.getElementById("ring-disk");
        if (ring) ring.setAttribute("stroke-dasharray", (Math.min(diskPct, 100) / 100 * 314.16).toFixed(2) + " 314.16");
        var dv = $(".vital-disk");
        if (dv) { dv.classList.toggle("warn", diskPct >= 75 && diskPct < 90); dv.classList.toggle("crit", diskPct >= 90); }
        charts.cpu && charts.cpu.push(m.cpu); tint("cpu", level(m.cpu));
        charts.mem && charts.mem.push(memPct); tint("mem", memPct >= 90 ? "crit" : memPct >= 75 ? "warn" : "ok");
        charts.load && charts.load.push(m.load1); tint("load", m.load1 / cores >= 1.5 ? "crit" : m.load1 / cores >= 1 ? "warn" : "ok");
        drawAll();
      };
      var drawAll = function () { var now = Date.now(); Object.keys(charts).forEach(function (k) { charts[k] && charts[k].draw(now); }); };
      var refresh = function () { return getJSON("/api/metrics?live=1").then(paint); };
      refresh().catch(function () {});
      poll(refresh, 3000);
      var resizeT = 0;
      window.addEventListener("resize", function () { clearTimeout(resizeT); resizeT = setTimeout(drawAll, 120); });
    }
  });

  guard("deploy log", function () {
    /* ---------- live deploy log ---------- */
    var logEl = $("pre[data-follow]");
    if (logEl) {
      var url = logEl.getAttribute("data-follow"), offset = 0, finished = false, stop = null;
      var statusEl = $("#deploy-status");
      var pull = function () {
        if (finished) return Promise.resolve();
        return getJSON(url + "?offset=" + offset).then(function (d) {
          var stick = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 24;
          if (d.data) { logEl.appendChild(doc.createTextNode(d.data)); if (stick) logEl.scrollTop = logEl.scrollHeight; }
          offset = d.offset;
          if (statusEl && d.status) { statusEl.textContent = d.status.replace(/_/g, " "); statusEl.className = "badge " + d.status; }
          if (d.done) { finished = true; if (stop) stop(); }
        });
      };
      pull().catch(function () {});
      stop = poll(pull, 2000);
    }
  });

  guard("uploads", function () {
    /* ---------- streamed uploads with progress ---------- */
    $$("form.js-upload").forEach(function (f) {
      var input = $("input[type=file]", f), st = $(".upload-status", f), bar = $(".progress", f);
      f.addEventListener("submit", function (ev) {
        ev.preventDefault();
        if (!input.files.length) return;
        var fd = new FormData();
        Array.prototype.forEach.call(input.files, function (x) { fd.append("file", x, x.name); });
        var xhr = new XMLHttpRequest(), btn = $("button", f);
        xhr.open("POST", f.getAttribute("data-action"));
        xhr.setRequestHeader("X-CSRF-Token", csrf);
        xhr.responseType = "json";
        if (bar) bar.classList.add("on");
        if (btn) btn.classList.add("is-busy");
        xhr.upload.onprogress = function (e) {
          if (!e.lengthComputable) return;
          var p = e.loaded / e.total * 100;
          if (bar) bar.firstElementChild.style.width = p.toFixed(1) + "%";
          st.textContent = "Uploading… " + p.toFixed(0) + "%";
        };
        xhr.onload = function () {
          if (xhr.status >= 200 && xhr.status < 300) { location.reload(); return; }
          if (btn) btn.classList.remove("is-busy");
          st.textContent = (xhr.response && xhr.response.error) || "Upload failed (HTTP " + xhr.status + ")";
        };
        xhr.onerror = function () { if (btn) btn.classList.remove("is-busy"); st.textContent = "Upload failed"; };
        xhr.send(fd);
      });
      input.addEventListener("change", function () {
        var n = input.files.length;
        st.textContent = n ? n + " file" + (n > 1 ? "s" : "") + " selected" : "";
      });
    });
  });

  guard("countdown", function () {
    /* ---------- firewall commit-confirmed countdown ---------- */
    var cd = $("#confirm-countdown");
    if (cd) {
      var left = parseInt(cd.getAttribute("data-seconds"), 10) || 0;
      var tick = setInterval(function () {
        if (left > 0) left--;
        cd.textContent = left + "s";
        if (!left) { clearInterval(tick); setTimeout(function () { location.reload(); }, 3000); }
      }, 1000);
    }
  });

  /* ---------- editors: Tab inserts spaces, Ctrl/Cmd+S saves, unsaved-changes guard ---------- */
  guard("editors", function () {
    $$("textarea.editor").forEach(function (ta) {
      var initial = ta.value, dirty = false;
      ta.addEventListener("input", function () { dirty = ta.value !== initial; });
      if (ta.form) ta.form.addEventListener("submit", function () { dirty = false; });
      window.addEventListener("beforeunload", function (ev) {
        if (dirty && !ta.readOnly) { ev.preventDefault(); ev.returnValue = ""; }
      });
      ta.addEventListener("keydown", function (ev) {
        if (ev.key === "Tab" && !ev.shiftKey && !ta.readOnly) {
          ev.preventDefault();
          var s = ta.selectionStart, e = ta.selectionEnd;
          ta.setRangeText("    ", s, e, "end");
          dirty = ta.value !== initial;
        } else if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "s" && !ta.readOnly) {
          ev.preventDefault();
          if (ta.form.requestSubmit) ta.form.requestSubmit(); else ta.form.submit();
        }
      });
    });
  });

  /* ---------- "/" focuses the filter field of the page ---------- */
  doc.addEventListener("keydown", function (ev) {
    if (ev.key !== "/" || ev.ctrlKey || ev.metaKey || ev.altKey) return;
    var t = ev.target, tag = t && t.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || (t && t.isContentEditable)) return;
    var f = $$("input[data-filter]").filter(function (i) { return i.offsetParent !== null; })[0];
    if (f) { ev.preventDefault(); f.focus(); f.select(); }
  });
  /* ---------- firewall: SSH brute-force toggle and custom rules ---------- */
  (function () {
    var form = $("textarea[name=ssh_sources]");
    var box = $("input[name=ssh_rate_limit]");
    if (form && box) {
      var hint = $("[data-brute-hint]");
      var textOpen = hint ? hint.textContent : "";
      var textLocked = "Not needed: SSH is already limited to the addresses above, nobody else can reach it.";
      var textAuto = "More than 10 new SSH connections per minute from one address ban it for 1 hour. Turned on automatically while SSH is open to everyone.";
      var locked = box.disabled;
      var sync = function () {
        var has = form.value.split(/\r?\n/).some(function (l) { return l.trim() !== ""; });
        if (has === locked) return;
        locked = has;
        if (has) { box.checked = false; box.disabled = true; } else { box.disabled = false; box.checked = true; }
        box.closest(".check").classList.toggle("is-locked", has);
        if (hint) hint.textContent = has ? textLocked : (textOpen && textOpen !== textLocked ? textOpen : textAuto);
      };
      box.closest(".check").classList.toggle("is-locked", locked);
      form.addEventListener("input", sync);
    }

    var root = $("[data-rules]");
    if (!root) return;
    var list = $("[data-rule-list]", root), tpl = $("template[data-rule-tpl]", root);
    var empty = $("[data-rule-empty]", root), count = $("[data-rule-count]", root), anyBox = $("[data-rule-any]", root);
    var srcRe = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]*)(\/\d{1,3})?$/;
    var rows = function () { return $$("[data-rule]", list); };
    var val = function (r, n) { return (r.querySelector("[name=" + n + "]").value || "").trim(); };
    function refresh() {
      var rs = rows(), open = 0, used = 0;
      rs.forEach(function (r) {
        var port = r.querySelector("[name=rule_port]"), src = r.querySelector("[name=rule_source]");
        var filled = val(r, "rule_port") !== "" || val(r, "rule_source") !== "" || val(r, "rule_comment") !== "";
        port.required = filled;
        var p = parseInt(port.value, 10);
        port.setCustomValidity(port.value !== "" && !(p >= 1 && p <= 65535) ? "Port must be 1-65535" : "");
        var sv = src.value.trim();
        src.setCustomValidity(sv !== "" && !srcRe.test(sv) ? "Enter an IP address or CIDR such as 203.0.113.0/24" : "");
        var isOpen = val(r, "rule_port") !== "" && sv === "";
        r.classList.toggle("is-open", isOpen);
        r.querySelector(".rule-open").hidden = !isOpen;
        if (isOpen) open++;
        if (val(r, "rule_port") !== "") used++;
      });
      empty.hidden = rs.length > 0;
      count.textContent = used ? used + (used === 1 ? " rule" : " rules") : "";
      anyBox.hidden = open === 0;
      if (open === 0) anyBox.querySelector("input").checked = false;
    }
    function add(port, proto, note) {
      if (port) {
        var dup = rows().filter(function (r) { return val(r, "rule_port") === String(port) && r.querySelector("[name=rule_proto]").value === proto; })[0];
        if (dup) { dup.classList.add("flash"); setTimeout(function () { dup.classList.remove("flash"); }, 900); return; }
      }
      var node = tpl.content.firstElementChild.cloneNode(true);
      list.appendChild(node);
      if (port) {
        node.querySelector("[name=rule_port]").value = port;
        node.querySelector("[name=rule_proto]").value = proto;
        node.querySelector("[name=rule_comment]").value = note || "";
        node.querySelector("[name=rule_source]").focus();
      } else {
        node.querySelector("[name=rule_port]").focus();
      }
      refresh();
    }
    root.addEventListener("click", function (ev) {
      var t = ev.target.closest ? ev.target.closest("[data-rule-add], [data-rule-del], [data-preset]") : null;
      if (!t) return;
      if (t.hasAttribute("data-rule-add")) add();
      else if (t.hasAttribute("data-rule-del")) { t.closest("[data-rule]").remove(); refresh(); }
      else { var p = t.getAttribute("data-preset").split("/"); add(p[0], p[1], p[2]); }
    });
    root.addEventListener("input", refresh);
    refresh();
  })();
})();
