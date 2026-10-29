/* Fleetboard's dashboard. Vanilla JS, no framework. Rules copied from Erynne's own pages: every
   piece of text goes through textContent (never innerHTML), every URL is relative so Mnemerynne's
   Remote proxy can serve this under /remote/fleetboard/, and the live feed is one EventSource that
   reconnects with backoff. The server says goodbye every five minutes so the proxy can re-check
   that the person is still signed in; a 401 on reconnect means they aren't. */
(function () {
  "use strict";

  // ------------------------------------------------------------------ helpers
  const $ = (id) => document.getElementById(id);                        // one element by id
  function el(tag, cls, text) {                                           // make an element; text is textContent only
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function svg(tag, attrs) {                                              // SVG elements need the namespace
    const e = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }
  async function api(method, url, body) {                                 // JSON in, JSON out; throws Error(detail) with .status
    const res = await fetch(url, {
      method, headers: body ? { "Content-Type": "application/json", "Accept": "application/json" } : { "Accept": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 204) return null;
    let data = null;
    try { data = await res.json(); } catch (e) { /* not JSON: the login page, or a proxy error */ }
    if (!res.ok) {
      const err = new Error((data && data.detail) || `HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return data;
  }
  const GIB = 1024 ** 3;
  function bytes(n) {                                                     // 6.1 GiB, 512 MiB
    if (n == null) return "–";
    if (n >= GIB) return (n / GIB).toFixed(n >= 100 * GIB ? 0 : 1) + " GiB";
    if (n >= 1024 ** 2) return Math.round(n / 1024 ** 2) + " MiB";
    return Math.round(n / 1024) + " KiB";
  }
  function rate(n) {                                                      // bytes/s → 1.2 MB/s
    if (n == null) return "–";
    if (n >= 1e9) return (n / 1e9).toFixed(2) + " GB/s";
    if (n >= 1e6) return (n / 1e6).toFixed(1) + " MB/s";
    if (n >= 1e3) return Math.round(n / 1e3) + " kB/s";
    return n + " B/s";
  }
  function uptime(s) {                                                    // 3d 4h, 2h 15m, 40m
    const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
  }
  const pct = (v) => v == null ? "–" : Math.round(v) + " %";
  const clamp = (v) => Math.max(0, Math.min(100, Number(v) || 0));

  // ------------------------------------------------------------------ theme
  function detectTheme() {                                                // follow Erynne's theme when framed by it
    try {
      const t = window.parent !== window && window.parent.document.documentElement.dataset.theme;
      return ["neon", "sakura", "plain"].includes(t) ? t : "neon";
    } catch (e) { return "neon"; }                                        // another origin, or opened on its own
  }
  function applyTheme() { document.documentElement.dataset.theme = detectTheme(); }
  applyTheme();
  try {                                                                   // live switches in Erynne's Preferences
    if (window.parent !== window) {
      new MutationObserver(applyTheme).observe(window.parent.document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    }
  } catch (e) { /* cross-origin: stay on the fallback */ }

  // ------------------------------------------------------------------ state
  const state = {
    hosts: [],                 // HostLive rows from the last tick
    rings: {},                 // id -> [RingPoint], seeded from api/ring, appended from ticks
    cards: {},                 // id -> the card's DOM pieces, so updates don't rebuild
    view: "live",
    source: null, backoff: 1000, stopped: false,
  };

  // ------------------------------------------------------------------ live stream
  function setConnection(ok, text) {
    $("light").classList.toggle("off", !ok);
    $("connection-text").textContent = text;
  }
  function connect() {                                                    // one EventSource; reconnects with backoff
    if (state.stopped || document.hidden) return;
    if (state.source) state.source.close();
    const es = new EventSource("api/live");
    state.source = es;
    es.addEventListener("tick", (ev) => {
      state.backoff = 1000;
      setConnection(true, "live");
      let data;
      try { data = JSON.parse(ev.data); } catch (e) { return; }
      onTick(data);
    });
    es.addEventListener("bye", () => { es.close(); connect(); });         // the server's 5-minute goodbye: reconnect at once
    es.onerror = async () => {
      es.close();
      setConnection(false, "reconnecting…");
      try {                                                               // why did it fail? ask something cheap
        const probe = await fetch("api/hosts", { headers: { "Accept": "application/json" } });
        if (probe.status === 401) return signedOut("You've been signed out of Mnemerynne. Reload to sign in again.");
        if (probe.status === 403) return signedOut("You no longer have access to Fleetboard.");
      } catch (e) { /* the server itself is away: keep retrying */ }
      setTimeout(connect, state.backoff);
      state.backoff = Math.min(state.backoff * 2, 30000);
    };
  }
  function signedOut(message) {                                           // stop for good and say why
    state.stopped = true;
    setConnection(false, "signed out");
    const b = $("banner");
    b.textContent = message;
    const btn = el("button", "small", "Reload");
    btn.type = "button";
    btn.onclick = () => location.reload();
    b.appendChild(btn);
    b.hidden = false;
  }
  document.addEventListener("visibilitychange", () => {                  // no stream for a hidden tab
    if (document.hidden) { if (state.source) state.source.close(); setConnection(false, "paused"); }
    else connect();
  });

  function onTick(ev) {
    state.hosts = ev.hosts;
    for (const h of ev.hosts) {
      let ring = state.rings[h.id];
      if (!ring) {                                                        // first sight of this host: fetch its last ten minutes
        ring = state.rings[h.id] = [];
        seedRing(h.id);
      }
      if (h.snapshot && h.reachable) {
        const s = h.snapshot;
        ring.push({ ts: ev.ts, cpu: s.cpu.percent, mem_used: s.memory.used_bytes,
                    gpu_util: s.gpus.length ? s.gpus[0].util_percent : null,
                    net_rx: s.network.reduce((a, n) => a + n.rx_bps, 0), net_tx: s.network.reduce((a, n) => a + n.tx_bps, 0) });
        if (ring.length > 300) ring.shift();
      }
    }
    renderCards();
    if (state.view === "hosts") renderHostsTable();
  }
  async function seedRing(id) {                                           // the ten minutes before the page opened
    try {
      const data = await api("GET", `api/ring?host=${id}`);
      if (!data || !Array.isArray(data.points)) return;
      const have = state.rings[id] || [];                                 // ticks that arrived while we were fetching
      const last = data.points.length ? data.points[data.points.length - 1].ts : 0;
      state.rings[id] = data.points.concat(have.filter((p) => p.ts > last)).slice(-300);
      renderCards();
    } catch (e) { /* the sparkline just starts now */ }
  }

  // ------------------------------------------------------------------ cards
  function meter(cls, label) {                                            // label | bar | value
    const row = el("div", `meter ${cls}`);
    const bar = el("div", "bar");
    const fill = el("span");
    bar.appendChild(fill);
    const value = el("span", "value", "–");
    row.append(el("span", "stat-label", label), bar, value);
    return { row, fill, value };
  }
  function sparkline(cls) {                                               // an SVG polyline we re-point every tick
    const s = svg("svg", { class: `spark ${cls}`, viewBox: "0 0 300 40", preserveAspectRatio: "none", "aria-hidden": "true" });
    s.appendChild(svg("line", { class: "base", x1: 0, y1: 39.5, x2: 300, y2: 39.5 }));
    const line = svg("polyline", { points: "" });
    s.appendChild(line);
    return { svg: s, line };
  }
  function drawSpark(line, points, pick, max) {                           // scale the ring to 300×40
    if (!points.length) { line.setAttribute("points", ""); return; }
    const n = points.length, top = max || Math.max(1, ...points.map(pick));
    const pts = points.map((p, i) => {
      const x = n === 1 ? 300 : (i / (n - 1)) * 300;
      const y = 39 - (clamp(pick(p) / top * 100) / 100) * 36;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    });
    line.setAttribute("points", pts.join(" "));
  }
  function buildCard(h) {                                                 // the DOM once; update() fills it every tick
    const card = el("article", "card");
    const head = el("div", "card-head");
    const title = el("h2", null, h.name);
    const pill = el("span", "pill");
    head.append(title, pill);
    const facts = el("p", "facts");
    const error = el("p", "error");
    const cpu = meter("cpu", "CPU");
    const cpuSpark = sparkline("cpu");
    const cpuLine = el("div", "line");
    const mem = meter("mem", "MEMORY");
    const memSpark = sparkline("mem");
    const gpus = el("div", "gpus");
    const net = el("div", "line");
    const disks = el("div", "disks");
    card.append(head, facts, error, cpu.row, cpuSpark.svg, cpuLine, mem.row, memSpark.svg, gpus, net, disks);
    return { card, title, pill, facts, error, cpu, cpuSpark, cpuLine, mem, memSpark, gpus, net, disks, gpuRows: [] };
  }
  function renderCards() {
    const wrap = $("cards");
    $("empty").hidden = state.hosts.length > 0;
    const seen = new Set();
    for (const h of state.hosts) {
      seen.add(h.id);
      let c = state.cards[h.id];
      if (!c) { c = state.cards[h.id] = buildCard(h); wrap.appendChild(c.card); }
      updateCard(c, h);
    }
    for (const id of Object.keys(state.cards)) {                          // removed hosts
      if (!seen.has(Number(id))) { state.cards[id].card.remove(); delete state.cards[id]; delete state.rings[id]; }
    }
    if (state.view === "history" && (history.host == null || $("history-host").options.length !== state.hosts.length)) {
      fillHistoryHosts();                                                 // the tab opened before the hosts arrived, or a host came or went
      if (history.host != null && !history.points.length) loadHistory();
    }
  }
  function updateCard(c, h) {
    const s = h.snapshot;
    c.title.textContent = h.name;
    c.card.classList.toggle("down", h.reachable === false);
    if (!h.enabled) { c.pill.className = "pill busy"; c.pill.textContent = "DISABLED"; }
    else if (h.reachable === true) { c.pill.className = "pill ok"; c.pill.textContent = `UP · ${h.latency_ms ?? "–"} ms`; }
    else if (h.reachable === false) { c.pill.className = "pill bad"; c.pill.textContent = "DOWN"; }
    else { c.pill.className = "pill busy"; c.pill.textContent = "WAITING"; }
    c.error.textContent = h.reachable === false ? `${h.address} ${h.error}` : "";
    c.error.hidden = !c.error.textContent;
    if (!s) { c.facts.textContent = h.address; return; }
    c.facts.textContent = `${s.host.os} · ${s.cpu.model} · up ${uptime(s.host.uptime_s)}`;
    c.cpu.fill.style.width = clamp(s.cpu.percent) + "%";
    c.cpu.value.textContent = pct(s.cpu.percent);
    const load = s.cpu.load1 != null ? `load ${s.cpu.load1.toFixed(2)} ${s.cpu.load5.toFixed(2)} ${s.cpu.load15.toFixed(2)}` : `${s.cpu.cores} threads`;
    c.cpuLine.textContent = "";
    c.cpuLine.append(el("span", null, load), el("span", null, s.cpu.freq_mhz ? (s.cpu.freq_mhz / 1000).toFixed(2) + " GHz" : ""));
    const memPct = s.memory.total_bytes ? s.memory.used_bytes / s.memory.total_bytes * 100 : 0;
    c.mem.fill.style.width = clamp(memPct) + "%";
    c.mem.value.textContent = `${bytes(s.memory.used_bytes)} / ${bytes(s.memory.total_bytes)}`;
    const ring = state.rings[h.id] || [];
    drawSpark(c.cpuSpark.line, ring, (p) => p.cpu, 100);
    drawSpark(c.memSpark.line, ring, (p) => p.mem_used, s.memory.total_bytes || 1);
    // GPUs: one block per card, built when the count changes
    if (c.gpuRows.length !== s.gpus.length) {
      c.gpus.textContent = "";
      c.gpuRows = s.gpus.map(() => {
        const name = el("p", "gpu-name");
        const util = meter("gpu", "GPU");
        const vram = meter("vram", "VRAM");
        const line = el("div", "line");
        c.gpus.append(name, util.row, vram.row, line);
        return { name, util, vram, line };
      });
    }
    s.gpus.forEach((g, i) => {
      const r = c.gpuRows[i];
      r.name.textContent = `${g.name} (${g.source})`;
      r.util.fill.style.width = clamp(g.util_percent) + "%";
      r.util.value.textContent = pct(g.util_percent);
      const vp = g.vram_total_bytes ? (g.vram_used_bytes || 0) / g.vram_total_bytes * 100 : 0;
      r.vram.fill.style.width = clamp(vp) + "%";
      r.vram.value.textContent = g.vram_total_bytes ? `${bytes(g.vram_used_bytes)} / ${bytes(g.vram_total_bytes)}` : "–";
      const bits = [];
      if (g.temp_c != null) bits.push(`${Math.round(g.temp_c)} °C`);
      if (g.power_w != null) bits.push(`${Math.round(g.power_w)} W`);
      if (g.fan_percent != null) bits.push(`fan ${Math.round(g.fan_percent)} %`);
      if (g.clock_mhz != null) bits.push(`${g.clock_mhz} MHz`);
      r.line.textContent = "";
      bits.forEach((b) => r.line.appendChild(el("span", null, b)));
    });
    // network and disks
    const rx = s.network.reduce((a, n) => a + n.rx_bps, 0), tx = s.network.reduce((a, n) => a + n.tx_bps, 0);
    c.net.textContent = "";
    c.net.append(el("span", null, `↓ ${rate(rx)}`), el("span", null, `↑ ${rate(tx)}`));
    c.net.title = s.network.map((n) => `${n.name}: ↓ ${rate(n.rx_bps)} ↑ ${rate(n.tx_bps)}`).join("\n");
    c.disks.textContent = "";
    for (const d of s.disks.slice(0, 6)) {
      const m = meter("disk", d.mount.length > 8 ? d.mount.slice(0, 7) + "…" : d.mount);
      m.row.title = `${d.mount} (${d.fs})`;
      m.fill.style.width = clamp(d.total_bytes ? d.used_bytes / d.total_bytes * 100 : 0) + "%";
      m.value.textContent = `${bytes(d.used_bytes)} / ${bytes(d.total_bytes)}`;
      c.disks.appendChild(m.row);
    }
  }

  // ------------------------------------------------------------------ hosts panel
  const form = $("host-form");
  function showFormError(text) { $("form-error").textContent = text || ""; }
  function hint(text) { $("form-hint").textContent = text || ""; }
  function resetForm() {
    form.reset();
    form.elements.id.value = "";
    $("save").textContent = "Add";
    $("cancel").hidden = true;
    hint(""); showFormError("");
  }
  async function refreshHosts() {
    try {
      const data = await api("GET", "api/hosts");
      state.hosts = data.hosts;
      const badge = $("token-badge");
      badge.textContent = data.token_set ? "token: set" : "token: NOT SET";
      badge.classList.toggle("bad", !data.token_set);
      renderHostsTable();
      renderCards();
    } catch (e) { showFormError(e.message); }
  }
  function renderHostsTable() {
    const body = $("hosts-table").querySelector("tbody");
    body.textContent = "";
    for (const h of state.hosts) {
      const tr = el("tr");
      const stateText = !h.enabled ? "disabled" : h.reachable === true ? "up" : h.reachable === false ? `down: ${h.error}` : "waiting";
      const edit = el("button", "small secondary", "Edit"); edit.type = "button";
      edit.onclick = () => { form.elements.id.value = h.id; form.elements.name.value = h.name; form.elements.address.value = h.address;
                             $("save").textContent = "Save"; $("cancel").hidden = false; hint(""); showFormError(""); form.elements.name.focus(); };
      const toggle = el("button", "small secondary", h.enabled ? "Disable" : "Enable"); toggle.type = "button";
      toggle.onclick = () => patch(h.id, { enabled: !h.enabled });
      const remove = el("button", "small danger", "Remove"); remove.type = "button";
      remove.onclick = async () => {
        if (!confirm(`Remove ${h.name} and its history?`)) return;
        try { await api("DELETE", `api/hosts/${h.id}`); await refreshHosts(); } catch (e) { showFormError(e.message); }
      };
      const actions = el("td", "actions");
      actions.append(edit, " ", toggle, " ", remove);
      tr.append(el("td", null, h.name), el("td", "mono", h.address), el("td", null, stateText),
                el("td", "mono", h.latency_ms != null ? h.latency_ms + " ms" : "–"),
                el("td", "mono", h.polled_s_ago != null ? h.polled_s_ago + " s ago" : "–"), actions);
      body.appendChild(tr);
    }
  }
  async function patch(id, body) {
    try { await api("PUT", `api/hosts/${id}`, body); await refreshHosts(); } catch (e) { showFormError(e.message); }
  }
  $("check").onclick = async () => {                                     // does it answer, before saving?
    showFormError(""); hint("checking…");
    $("check").disabled = true;
    try {
      const r = await api("POST", "api/hosts/check", { address: form.elements.address.value });
      hint(`${r.address} answers in ${r.latency_ms} ms (${r.hostname}, agent ${r.agent})`);
    } catch (e) { hint(""); showFormError(e.message); }
    finally { $("check").disabled = false; }
  };
  form.onsubmit = async (ev) => {
    ev.preventDefault();
    showFormError("");
    const id = form.elements.id.value;
    const body = { name: form.elements.name.value, address: form.elements.address.value };
    $("save").disabled = true;
    try {
      if (id) await api("PUT", `api/hosts/${id}`, body); else await api("POST", "api/hosts", body);
      resetForm();
      await refreshHosts();
    } catch (e) { showFormError(e.message); }
    finally { $("save").disabled = false; }
  };
  $("cancel").onclick = resetForm;

  // ------------------------------------------------------------------ history view
  // Four charts drawn from api/history, a scrubber that moves a cursor through them and fills the
  // legend with the values at that moment. Refreshes every minute while the tab is showing.
  const history = { host: null, range: 21600, points: [], charts: [], timer: null };
  const CHARTS = [                                                        // what each chart draws
    { title: "CPU", unit: "%", max: 100, series: [{ key: "cpu", label: "cpu %", fmt: pct }, { key: "load1", label: "load 1 m", fmt: (v) => v == null ? "–" : v.toFixed(2), axis: "right" }] },
    { title: "MEMORY", unit: "GiB", series: [{ key: "mem_used", label: "used", fmt: bytes }], maxFrom: "mem_total" },
    { title: "GPU", unit: "%", max: 100, series: [{ key: "gpu_util", label: "util %", fmt: pct }, { key: "gpu_temp", label: "temp °C", fmt: (v) => v == null ? "–" : Math.round(v) + " °C" }] },
    { title: "NETWORK", unit: "B/s", series: [{ key: "net_rx", label: "down", fmt: rate }, { key: "net_tx", label: "up", fmt: rate }] },
  ];
  function buildCharts() {
    const wrap = $("charts");
    wrap.textContent = "";
    history.charts = CHARTS.map((def) => {
      const box = el("div", "chart");
      const head = el("div", "chart-head");
      const title = el("span", null, def.title);
      const maxLabel = el("span", null, "");
      head.append(title, maxLabel);
      const s = svg("svg", { viewBox: "0 0 600 130", preserveAspectRatio: "none", "aria-hidden": "true" });
      [0.25, 0.5, 0.75].forEach((f) => s.appendChild(svg("line", { class: "grid", x1: 0, y1: 130 * f, x2: 600, y2: 130 * f })));
      const lines = def.series.map((_, i) => { const p = svg("polyline", { class: `s${i}`, points: "" }); s.appendChild(p); return p; });
      const cursor = svg("line", { class: "cursor", x1: -10, y1: 0, x2: -10, y2: 130 });
      s.appendChild(cursor);
      const legend = el("div", "series");
      def.series.forEach((se, i) => legend.appendChild(el("span", `s${i}`, se.label)));
      box.append(head, s, legend);
      wrap.appendChild(box);
      return { def, maxLabel, lines, cursor };
    });
  }
  function drawCharts() {
    const pts = history.points, n = pts.length;
    $("history-hint").textContent = n ? "" : "No history for this host yet; it fills in as the server polls.";
    for (const c of history.charts) {
      const maxes = c.def.series.map((se) => c.def.max || Math.max(1, ...pts.map((p) => p[c.def.maxFrom || se.key] ?? 0)));
      c.maxLabel.textContent = c.def.max ? `0–${c.def.max} ${c.def.unit}` : `max ${c.def.series[0].fmt(maxes[0])}`;
      c.def.series.forEach((se, i) => {
        const top = maxes[i];
        const coords = [];
        pts.forEach((p, k) => {
          const v = p[se.key];
          if (v == null) return;                                           // a gap: the line simply skips
          const x = n === 1 ? 600 : (k / (n - 1)) * 600;
          const y = 128 - clamp(v / top * 100) / 100 * 124;
          coords.push(`${x.toFixed(1)},${y.toFixed(1)}`);
        });
        c.lines[i].setAttribute("points", coords.join(" "));
      });
    }
    const scrub = $("scrub");
    scrub.max = Math.max(0, n - 1);
    scrub.value = scrub.max;
    scrubTo(Number(scrub.value));
  }
  function scrubTo(k) {                                                   // the cursor and the legend follow the slider
    const pts = history.points, n = pts.length;
    const legend = $("legend");
    legend.textContent = "";
    if (!n) { $("scrub-time").textContent = "–"; return; }
    const p = pts[Math.min(k, n - 1)];
    const x = n === 1 ? 600 : (k / (n - 1)) * 600;
    history.charts.forEach((c) => { c.cursor.setAttribute("x1", x); c.cursor.setAttribute("x2", x); });
    $("scrub-time").textContent = new Date(p.ts * 1000).toLocaleString();
    for (const def of CHARTS) for (const se of def.series) {
      legend.append(el("dt", null, `${def.title} ${se.label}`), el("dd", null, se.fmt(p[se.key])));
    }
  }
  async function loadHistory() {
    if (history.host == null) return;
    const to = Math.floor(Date.now() / 1000), from = to - history.range;
    try {
      const data = await api("GET", `api/history?host=${history.host}&from=${from}&to=${to}`);
      history.points = data.points || [];
      drawCharts();
    } catch (e) { $("history-hint").textContent = e.message; }
  }
  function fillHistoryHosts() {
    const sel = $("history-host");
    const current = history.host;
    sel.textContent = "";
    for (const h of state.hosts) {
      const o = el("option", null, h.name);
      o.value = h.id;
      sel.appendChild(o);
    }
    if (state.hosts.length && !state.hosts.some((h) => h.id === current)) history.host = state.hosts[0].id;
    sel.value = history.host ?? "";
  }
  $("history-host").onchange = (ev) => { history.host = Number(ev.target.value); loadHistory(); };
  document.querySelectorAll(".range button").forEach((b) => {
    b.onclick = () => {
      document.querySelectorAll(".range button").forEach((o) => o.classList.toggle("active", o === b));
      history.range = Number(b.dataset.range);
      loadHistory();
    };
  });
  $("scrub").oninput = (ev) => scrubTo(Number(ev.target.value));
  function showHistory(on) {                                              // start/stop the minute refresh with the tab
    clearInterval(history.timer);
    history.timer = null;
    if (!on) return;
    if (!history.charts.length) buildCharts();
    fillHistoryHosts();
    loadHistory();
    history.timer = setInterval(() => { if (!document.hidden) loadHistory(); }, 60000);
  }

  // ------------------------------------------------------------------ tabs and start
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.onclick = () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === tab));
      state.view = tab.dataset.view;
      $("view-live").hidden = state.view !== "live";
      $("view-hosts").hidden = state.view !== "hosts";
      $("view-history").hidden = state.view !== "history";
      if (state.view === "hosts") refreshHosts();
      showHistory(state.view === "history");
      try { history.replaceState(null, "", state.view === "live" ? location.pathname : `#${state.view}`); } catch (e) { /* fine */ }
    };
  });
  (async () => {
    const wanted = document.querySelector(`.tab[data-view="${location.hash.slice(1)}"]`);   // #history, #hosts deep links
    if (wanted) wanted.click();
    try {
      const h = await api("GET", "healthz");
      $("version").textContent = `v${h.version}`;
      $("footer-version").textContent = `server ${h.version}`;
    } catch (e) { /* the stream will say */ }
    await refreshHosts();
    connect();
  })();
})();
