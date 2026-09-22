"use strict";

const STORAGE_KEY = "gecit-panel-token";
const POLL_MS = 1000;

// The bootstrap URL carries the token once. Stash it and take it out of the
// address bar so it does not end up in a bookmark or a screenshot.
//
// localStorage rather than sessionStorage: the panel is a page you come back
// to, and a token that died with the tab would mean digging the URL out of
// `gecit status` every time. Both are scoped to this origin, which serves
// nothing third party.
function readToken() {
  const fromQuery = new URLSearchParams(location.search).get("t");
  if (fromQuery) {
    store(fromQuery);
    history.replaceState(null, "", location.pathname);
    return fromQuery;
  }
  try {
    return localStorage.getItem(STORAGE_KEY) || "";
  } catch {
    return "";
  }
}

function store(token) {
  try {
    localStorage.setItem(STORAGE_KEY, token);
  } catch {
    // A browser with storage blocked still works for this tab.
  }
}

// forget drops a token the panel has stopped accepting, so a stale one from a
// reinstall does not keep priming the gate with something that cannot work.
function forget() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing to clear.
  }
}

let token = readToken();

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    let message = res.status + " " + res.statusText;
    try {
      const body = await res.json();
      if (body.error) message = body.error;
    } catch {
      // Not every failure has a JSON body.
    }
    const err = new Error(message);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

const $ = (id) => document.getElementById(id);

function show(el, visible) {
  el.classList.toggle("hidden", !visible);
}

function text(tag, value, className) {
  const el = document.createElement(tag);
  el.textContent = value;
  if (className) el.className = className;
  return el;
}

// The gate

function openGate(message) {
  show($("gate"), true);
  show($("app"), false);
  if (message) {
    $("gate-error").textContent = message;
    show($("gate-error"), true);
  }
}

$("gate-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const value = $("gate-token").value.trim();
  if (!value) return;
  token = value;
  store(value);
  show($("gate"), false);
  show($("app"), true);
  poll();
});

// Tabs

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    for (const other of document.querySelectorAll(".tab")) {
      other.classList.toggle("active", other === tab);
    }
    for (const name of ["overview", "activity", "logs", "config"]) {
      show($("tab-" + name), name === tab.dataset.tab);
    }
  });
}

// Lifecycle

$("btn-start").addEventListener("click", () => lifecycle("/api/start"));
$("btn-stop").addEventListener("click", () => lifecycle("/api/stop"));

async function lifecycle(path) {
  try {
    await api(path, { method: "POST" });
    banner("");
  } catch (err) {
    banner(err.message);
  }
  poll();
}

function banner(message) {
  $("banner").textContent = message;
  show($("banner"), message !== "");
}

// State

const COUNTERS = [
  ["connections", "connections"],
  ["fakes_injected", "fakes injected"],
  ["inject_errors", "injection errors"],
  ["dns_queries", "DNS queries"],
  ["dns_errors", "DNS errors"],
];

function renderState(state) {
  const pill = $("state-pill");
  pill.textContent = state.status.running ? "running" : "stopped";
  pill.className = "pill " + (state.status.running ? "running" : "stopped");

  $("mode").textContent = state.status.running ? state.status.mode : "";
  $("uptime").textContent = state.status.running ? uptime(state.status.started_at) : "";
  show($("btn-start"), !state.status.running);
  show($("btn-stop"), state.status.running);

  if (state.status.last_error) banner(state.status.last_error);

  const counters = $("counters");
  counters.replaceChildren();
  for (const [key, label] of COUNTERS) {
    const box = text("div", "", "counter");
    box.append(text("div", (state.stats[key] ?? 0).toLocaleString(), "value"));
    box.append(text("div", label, "label"));
    counters.append(box);
  }

  const platform = $("platform");
  platform.replaceChildren();
  for (const fact of state.platform || []) {
    const row = document.createElement("tr");
    row.append(text("td", fact.name), text("td", fact.value));
    platform.append(row);
  }

  renderActivity(state.activity || []);

  if ($("loglevel").value !== state.log_level) $("loglevel").value = state.log_level;
  if (!configDirty) renderConfig(state.config);
}

function uptime(startedAt) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(startedAt)) / 1000));
  const parts = [
    [Math.floor(seconds / 86400), "d"],
    [Math.floor(seconds / 3600) % 24, "h"],
    [Math.floor(seconds / 60) % 60, "m"],
    [seconds % 60, "s"],
  ].filter(([value], i) => value > 0 || i === 3);
  return "up " + parts.map(([value, unit]) => value + unit).join(" ");
}

function renderActivity(entries) {
  const body = $("activity").querySelector("tbody");
  body.replaceChildren();
  for (const entry of entries) {
    const fields = entry.fields || {};
    const row = document.createElement("tr");
    row.append(
      text("td", clock(entry.time)),
      text("td", fields.event === "dns" ? "resolved" : "injected"),
      text("td", fields.dst || fields.domain || ""),
      text("td", fields.event === "dns" ? fields.ips || "" : "ttl " + (fields.ttl || "")),
    );
    body.append(row);
  }
}

function clock(value) {
  return new Date(value).toLocaleTimeString();
}

// Logs

let since = 0;

$("loglevel").addEventListener("change", async () => {
  try {
    await api("/api/loglevel", {
      method: "POST",
      body: JSON.stringify({ level: $("loglevel").value }),
    });
    banner("");
  } catch (err) {
    banner(err.message);
  }
});

function renderLogs(payload) {
  const pre = $("logs");
  for (const entry of payload.entries || []) {
    const line = text("div", format(entry), "lvl-" + entry.level);
    pre.append(line);
  }
  while (pre.childElementCount > 2000) pre.removeChild(pre.firstChild);
  if ($("follow").checked) pre.scrollTop = pre.scrollHeight;
  since = payload.latest;
}

function format(entry) {
  const fields = Object.entries(entry.fields || {})
    .filter(([key]) => key !== "event")
    .map(([key, value]) => key + "=" + value)
    .join(" ");
  return [clock(entry.time), entry.level.toUpperCase().padEnd(5), entry.msg, fields]
    .filter(Boolean)
    .join("  ");
}

// Config

// panel_enabled and panel_addr are deliberately absent: turning the panel off
// or moving it from the panel takes the page away from whoever is using it.
// Both stay editable in the config file and on the command line, and a save
// carries their current values through untouched.
const FIELDS = [
  { key: "ports", label: "ports", type: "ports" },
  { key: "fake_ttl", label: "fake_ttl", type: "number" },
  { key: "doh_enabled", label: "doh_enabled", type: "checkbox" },
  { key: "doh_upstream", label: "doh_upstream", type: "doh" },
  { key: "interface", label: "interface", type: "text" },
  { key: "verbose", label: "verbose", type: "checkbox" },
  { key: "mss", label: "mss (Linux)", type: "number" },
  { key: "restore_after_bytes", label: "restore_after_bytes (Linux)", type: "number" },
  { key: "restore_mss", label: "restore_mss (Linux)", type: "number" },
  { key: "cgroup_path", label: "cgroup_path (Linux)", type: "text" },
];

const CUSTOM_DOH = "__custom__";

let configDirty = false;
let loadedConfig = null;

function renderConfig(view) {
  if (!view) return;
  loadedConfig = view.values;
  $("config-path").textContent = view.path;

  const form = $("config-form");
  form.replaceChildren();

  for (const field of FIELDS) {
    if (field.type === "doh") {
      form.append(labelFor(field), dohPicker(view));
      appendOverrideNote(form, view, field);
      continue;
    }

    const input = document.createElement("input");
    input.id = "cfg-" + field.key;
    const value = view.values[field.key];

    if (field.type === "checkbox") {
      input.type = "checkbox";
      input.checked = Boolean(value);
    } else if (field.type === "ports") {
      input.type = "text";
      input.value = (value || []).join(", ");
    } else {
      input.type = field.type;
      input.value = value ?? "";
    }
    input.addEventListener("input", () => {
      configDirty = true;
    });
    input.addEventListener("change", () => {
      configDirty = true;
    });

    form.append(labelFor(field, input.id), input);
    appendOverrideNote(form, view, field);
  }
}

function labelFor(field, inputId) {
  const label = document.createElement("label");
  label.textContent = field.label;
  if (inputId) label.setAttribute("for", inputId);
  return label;
}

function appendOverrideNote(form, view, field) {
  const overriding = (view.overridden_by_flag || {})[field.key];
  if (!overriding) return;
  form.append(
    text("p", "--" + overriding + " was passed on the command line and wins over this file", "note"),
  );
}

// dohPicker offers the presets the resolver accepts and falls back to a text
// box, which is also where a comma-separated fallback list goes.
function dohPicker(view) {
  const value = view.values.doh_upstream || "";
  const presets = view.doh_presets || [];
  const custom = !presets.includes(value);

  const select = document.createElement("select");
  select.id = "cfg-doh_upstream";
  for (const name of presets) {
    select.append(new Option(name, name));
  }
  select.append(new Option("custom https URL", CUSTOM_DOH));
  select.value = custom ? CUSTOM_DOH : value;

  const input = document.createElement("input");
  input.id = "cfg-doh_upstream-custom";
  input.type = "text";
  input.placeholder = "https://dns.example/dns-query, or a comma-separated list";
  input.value = custom ? value : "";
  show(input, custom);

  select.addEventListener("change", () => {
    configDirty = true;
    show(input, select.value === CUSTOM_DOH);
    if (select.value === CUSTOM_DOH) input.focus();
  });
  input.addEventListener("input", () => {
    configDirty = true;
  });

  const box = document.createElement("div");
  box.className = "stack";
  box.append(select, input);
  return box;
}

function collectConfig() {
  const values = { ...loadedConfig };
  for (const field of FIELDS) {
    const input = $("cfg-" + field.key);
    if (!input) continue;

    if (field.type === "doh") {
      values[field.key] =
        input.value === CUSTOM_DOH ? $("cfg-doh_upstream-custom").value.trim() : input.value;
    } else if (field.type === "checkbox") {
      values[field.key] = input.checked;
    } else if (field.type === "ports") {
      values[field.key] = input.value
        .split(",")
        .map((p) => parseInt(p.trim(), 10))
        .filter((p) => !Number.isNaN(p));
    } else if (field.type === "number") {
      values[field.key] = parseInt(input.value, 10) || 0;
    } else {
      values[field.key] = input.value;
    }
  }
  return values;
}

$("btn-save").addEventListener("click", () => save(false));
$("btn-apply").addEventListener("click", () => save(true));

async function save(apply) {
  const status = $("config-status");
  status.textContent = "saving...";
  status.className = "muted";

  try {
    await api("/api/config", { method: "PUT", body: JSON.stringify(collectConfig()) });
    configDirty = false;
    if (apply) {
      status.textContent = "applying...";
      await api("/api/apply", { method: "POST" });
      status.textContent = "applied";
    } else {
      status.textContent = "saved, apply to restart the engine on it";
    }
    banner("");
  } catch (err) {
    status.textContent = err.message;
    status.className = "error";
  }
  poll();
}

// Polling

// Applying a config change restarts the engine, and the state handler waits on
// that. Without this guard the interval would stack requests behind it.
let polling = false;

async function poll() {
  if (!token) {
    openGate("");
    return;
  }
  if (polling) return;
  polling = true;
  try {
    const [state, logs] = await Promise.all([
      api("/api/state"),
      api("/api/logs?since=" + since),
    ]);
    show($("gate"), false);
    show($("app"), true);
    renderState(state);
    renderLogs(logs);
  } catch (err) {
    if (err.status === 401) {
      forget();
      token = "";
      openGate("That token was not accepted.");
      return;
    }
    banner(err.message);
  } finally {
    polling = false;
  }
}

poll();
setInterval(poll, POLL_MS);
