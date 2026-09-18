/* ==========================================================
   PULSE OPTIMIZER â€” Control Panel Frontend
   app.js â€” Main application logic
   ========================================================== */

"use strict";

/** Authenticated fetch â€” always send session cookies */
async function apiFetch(url, options = {}) {
  const opts = { credentials: "include", ...options };
  opts.headers = { ...(options.headers || {}) };
  const res = await fetch(url, opts);
  if (res.status === 401 && !String(url).includes("/api/admin/login") && !String(url).includes("/api/admin/session")) {
    showLoginScreen("Session expired. Please sign in again.");
  }
  return res;
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeJsString(str) {
  return String(str ?? "")
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "\\'")
    .replace(/\r/g, "")
    .replace(/\n/g, "\\n");
}

const TWEAKS = [
  { id: 1,  name: "1:1 Raw Mouse Input & Linear Curve",     desc: "Disables pointer acceleration and flattens response curve for true 1:1 pixel precision." },
  { id: 2,  name: "High-Speed Keyboard Latency (0ms Delay)", desc: "Sets 0 repeat delay and max 31 repeat rate for instant mechanical response." },
  { id: 3,  name: "MMCSS Gaming Thread & GPU Priority 8",   desc: "Prioritizes foreground game threads and GPU processing inside the Multimedia Scheduler." },
  { id: 4,  name: "Hardware GPU Scheduling (HAGS)",         desc: "Reduces GPU latency and frees CPU scheduling overhead via hardware scheduler coprocessor." },
  { id: 5,  name: "Disable Game DVR & Background Capture",  desc: "Stops background video capture buffer and eliminates 1% low FPS micro-stuttering." },
  { id: 6,  name: "Win32 CPU Quantum Priority (0x26 Boost)", desc: "Allocates maximum CPU time-slices and priority to the active foreground game." },
  { id: 7,  name: "MenuShowDelay to 0ms (Instant UI)",      desc: "Removes Windows shell animation wait-time and makes context menus open instantly." },
  { id: 8,  name: "Disable Network Throttling Index",       desc: "Stops Windows from throttling network packets during gaming or multimedia playback." },
  { id: 9,  name: "Set SystemResponsiveness to 0%",         desc: "Gives active game 100% network & CPU priority instead of reserving 20% for background tasks." },
  { id: 10, name: "0.5ms Timer Resolution Enforcer",        desc: "Forces Windows kernel timer resolution to 0.5ms for lowest frame variance and jitter." },
  { id: 11, name: "GPU MSI Mode (Message Signaled Interrupts)", desc: "Configures GPU PCIe controller to high-priority MSI mode to slash DPC latency." },
  { id: 12, name: "Disable CPU Core Parking (100% Readiness)", desc: "Unparks all physical and logical CPU cores to ensure maximum clock speed readiness." },
  { id: 13, name: "Disable MPO (Multiplane Overlay Stutter Fix)", desc: "Disables DWM Multiplane Overlays to fix windowed gaming stutter and screen flickers." },
  { id: 14, name: "Disable Windows Delivery Optimization",  desc: "Stops Windows from using your upload bandwidth to seed updates to other PCs." },
  { id: 15, name: "Disable SysMain / SuperFetch Disk Thrashing", desc: "Eliminates unnecessary background caching and disk I/O on NVMe SSD drives." },
  { id: 16, name: "Disable DiagTrack Telemetry & Logging",  desc: "Disables telemetry event tracing and background diagnostic diagnostics." },
];

let liveConfig = null;
let maintenanceTweaks = new Set();
let selectedFile = null;
let clientSideSHA = "";
let isAuthenticated = false;

document.addEventListener("DOMContentLoaded", () => {
  bindLogin();
  bootstrapAuth();
});

function showLoginScreen(message) {
  isAuthenticated = false;
  const login = document.getElementById("login-screen");
  const app = document.getElementById("app-root");
  if (login) login.hidden = false;
  if (app) app.hidden = true;
  const err = document.getElementById("login-error");
  if (err) {
    if (message) {
      err.hidden = false;
      err.textContent = message;
    } else {
      err.hidden = true;
      err.textContent = "";
    }
  }
}

function showAppScreen() {
  isAuthenticated = true;
  const login = document.getElementById("login-screen");
  const app = document.getElementById("app-root");
  if (login) login.hidden = true;
  if (app) app.hidden = false;
}

function bindLogin() {
  const form = document.getElementById("login-form");
  if (!form) return;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value;
    const btn = document.getElementById("login-submit");
    const err = document.getElementById("login-error");
    btn.disabled = true;
    btn.textContent = "Signing inâ€¦";
    err.hidden = true;
    try {
      const res = await apiFetch("/api/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.success) {
        err.hidden = false;
        err.textContent = data.error || "Invalid credentials";
        return;
      }
      document.getElementById("login-password").value = "";
      await enterAuthenticatedApp();
    } catch (ex) {
      err.hidden = false;
      err.textContent = "Cannot reach server. Is it running?";
    } finally {
      btn.disabled = false;
      btn.textContent = "Sign In";
    }
  });

  const logoutBtn = document.getElementById("btn-logout");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      try {
        await apiFetch("/api/admin/logout", { method: "POST" });
      } catch (_) { /* ignore */ }
      showLoginScreen();
    });
  }
}

async function bootstrapAuth() {
  try {
    const health = await fetch("/api/health", { credentials: "include" });
    const statusEl = document.getElementById("server-status-text");
    if (health.ok) {
      if (statusEl) statusEl.textContent = "Server Online";
    } else if (statusEl) {
      statusEl.textContent = "Server Unreachable";
    }
  } catch (_) {
    const statusEl = document.getElementById("server-status-text");
    if (statusEl) statusEl.textContent = "Server Unreachable";
  }

  try {
    const res = await apiFetch("/api/admin/session");
    if (res.ok) {
      await enterAuthenticatedApp();
      return;
    }
  } catch (_) { /* fall through to login */ }
  showLoginScreen();
}

async function enterAuthenticatedApp() {
  if (window.__pulseAppReady) {
    showAppScreen();
    await loadLiveData();
    return;
  }
  window.__pulseAppReady = true;
  showAppScreen();
  buildTweakGrid();
  bindNavigation();
  bindPublisher();
  bindMaintenanceButtons();
  bindConfigEditor();
  bindUsersManagement();
  const refresh = document.getElementById("btn-refresh");
  if (refresh && !refresh.dataset.bound) {
    refresh.dataset.bound = "1";
    refresh.addEventListener("click", () => loadLiveData());
  }
  await loadLiveData();
}

async function loadUsersData() {
  const container = document.getElementById("users-table-container");
  if (!container) return;
  try {
    const res = await apiFetch("/api/admin/keys");
    if (!res.ok) throw new Error("unauthorized");
    const keysMap = await res.json();
    const keys = Object.values(keysMap);

    if (keys.length === 0) {
      container.innerHTML = '<div class="empty-state">No product keys or user registrations generated yet.</div>';
      return;
    }

    let html = `
      <table style="width:100%;border-collapse:collapse;margin-top:12px;color:#cbd5e1;font-size:13px;">
        <thead>
          <tr style="text-align:left;border-bottom:1px solid rgba(255,255,255,0.1);color:#94a3b8;padding-bottom:8px;">
            <th style="padding:10px;">Product Key</th>
            <th style="padding:10px;">User & HWID</th>
            <th style="padding:10px;">Duration</th>
            <th style="padding:10px;">Status</th>
            <th style="padding:10px;">Expires / Frozen</th>
            <th style="padding:10px;text-align:right;">Admin Actions</th>
          </tr>
        </thead>
        <tbody>
    `;

    keys.forEach(k => {
      let badgeClass = "badge-green";
      let statusText = "ACTIVE";
      if (k.revoked) { badgeClass = "badge-red"; statusText = "REVOKED"; }
      else if (k.is_frozen) { badgeClass = "badge-purple"; statusText = "FROZEN"; }
      else if (!k.is_activated) { badgeClass = "badge-amber"; statusText = "UNACTIVATED"; }

      const expStr = k.duration_days === 0 ? "Lifetime" : (k.is_activated ? (k.is_frozen ? "Frozen (Paused)" : new Date(k.expires_at * 1000).toLocaleString()) : "Awaiting First Auth");
      const safeUser = escapeHtml(k.username || "");
      const safeHwid = escapeHtml((k.bound_hwid || "").slice(0, 14));
      const safeKey = escapeHtml(k.key);
      const jsKey = escapeJsString(k.key);
      const jsHwid = escapeJsString(k.bound_hwid || "");
      const jsIp = escapeJsString(k.bound_ip || "");
      const userStr = k.username
        ? `<b>${safeUser}</b><br><span style="font-size:11px;color:#64748b;">${safeHwid}...</span>`
        : `<span style="color:#64748b;">Not Redeemed Yet</span>`;

      html += `
        <tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
          <td style="padding:10px;font-family:monospace;font-weight:bold;color:#00D2FF;">${safeKey}</td>
          <td style="padding:10px;">${userStr}</td>
          <td style="padding:10px;">${k.duration_days === 0 ? "Lifetime" : k.duration_days + " Days"}</td>
          <td style="padding:10px;"><span class="badge ${badgeClass}">${statusText}</span></td>
          <td style="padding:10px;font-size:12px;">${expStr}</td>
          <td style="padding:10px;text-align:right;">
            <button class="btn btn-secondary btn-small" onclick="adminAddTime('${jsKey}')">+30D</button>
            <button class="btn btn-secondary btn-small" onclick="adminToggleFreeze('${jsKey}', ${!k.is_frozen})">${k.is_frozen ? "ðŸ”¥ Unfreeze" : "ðŸ§Š Freeze"}</button>
            <button class="btn btn-secondary btn-small" title="Unfreeze key if frozen and reset freeze quota to 0" onclick="adminResetFreezes('${jsKey}')">ðŸ”„ Reset Freezes</button>
            <button class="btn btn-secondary btn-small" onclick="adminRevoke('${jsKey}')">ðŸš« Revoke</button>
            ${k.bound_hwid ? `<button class="btn btn-secondary btn-small" style="color:#ef4444;" onclick="adminBan('${jsKey}', '${jsHwid}', '${jsIp}')">â›” Ban</button>` : ""}
            <button class="btn btn-secondary btn-small" style="color:#f87171;" onclick="adminDeleteKey('${jsKey}')">ðŸ—‘ï¸ Delete</button>
            <button class="btn btn-primary btn-small" onclick="adminViewLogs('${jsKey}')">ðŸ“‹ Logs</button>
          </td>
        </tr>
      `;
    });

    html += `</tbody></table>`;
    container.innerHTML = html;
  } catch (err) {
    console.error("Failed to load users keys:", err);
    container.innerHTML = '<div class="empty-state">Failed to load user keys from server.</div>';
  }
}

function bindUsersManagement() {
  const btn = document.getElementById("btn-generate-key");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    const sel = document.getElementById("key-duration-select");
    const days = parseInt(sel.value, 10);
    try {
      const res = await apiFetch("/api/admin/generate-key", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ duration_days: days })
      });
      const data = await res.json();
      if (data.success) {
        document.getElementById("generated-key-container").style.display = "block";
        document.getElementById("generated-key-display").textContent = data.key.key;
        showToast(`Key generated: ${data.key.key}`);
        loadUsersData();
      } else { showToast("Key generation failed.", "error"); }
    } catch(err) { showToast("Network error during key generation.", "error"); }
  });
}

window.adminAddTime = async function(key) {
  try {
    const res = await apiFetch("/api/admin/add-time", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ key, days: 30 })
    });
    const data = await res.json();
    if (data.success) { showToast(`Added 30 days to ${key}`); loadUsersData(); }
  } catch(e) { showToast("Action failed.", "error"); }
};

window.adminToggleFreeze = async function(key, freeze) {
  try {
    const res = await apiFetch("/api/admin/freeze-key", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ key, freeze })
    });
    const data = await res.json();
    if (data.success) { showToast(`Key ${key} ${freeze ? "Frozen" : "Unfrozen"}`); loadUsersData(); }
  } catch(e) { showToast("Action failed.", "error"); }
};

window.adminResetFreezes = async function(key) {
  if (!confirm(`Reset freeze quota for ${key} and unfreeze it if currently frozen?`)) return;
  try {
    const res = await apiFetch("/api/admin/reset-freezes", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ key })
    });
    const data = await res.json();
    if (data.success) { showToast(`Reset freezes & unfroze ${key}`); loadUsersData(); }
    else { showToast(data.error || "Failed to reset freezes.", "error"); }
  } catch(e) { showToast("Action failed.", "error"); }
};

window.adminDeleteKey = async function(key) {
  if (!confirm(`Are you sure you want to permanently DELETE key ${key} from the server? This cannot be undone.`)) return;
  try {
    const res = await apiFetch("/api/admin/delete-key", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ key })
    });
    const data = await res.json();
    if (data.success) { showToast(`Deleted key ${key}`); loadUsersData(); }
    else { showToast(data.error || "Failed to delete key.", "error"); }
  } catch(e) { showToast("Action failed.", "error"); }
};

window.adminRevoke = async function(key) {
  if (!confirm(`Are you sure you want to revoke key ${key}?`)) return;
  try {
    const res = await apiFetch("/api/admin/revoke-key", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ key })
    });
    const data = await res.json();
    if (data.success) { showToast(`Revoked key ${key}`); loadUsersData(); }
  } catch(e) { showToast("Action failed.", "error"); }
};

window.adminBan = async function(key, hwid, ip) {
  if (!confirm(`Are you sure you want to BAN HWID ${hwid}? This device will be safely self-cleaned and blocked.`)) return;
  try {
    const res = await apiFetch("/api/admin/ban-user", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ key, hwid, ip })
    });
    const data = await res.json();
    if (data.success) { showToast(`Banned HWID ${hwid}`); loadUsersData(); }
  } catch(e) { showToast("Action failed.", "error"); }
};

window.adminViewLogs = async function(key) {
  try {
    const res = await apiFetch(`/api/admin/user-logs?key=${encodeURIComponent(key)}`);
    const logs = await res.json();
    if (!logs || logs.length === 0) {
      alert(`No activity logs recorded for key ${key} yet.`);
      return;
    }
    let msg = `Activity Timeline Log for ${key}:\n\n`;
    logs.forEach(l => {
      msg += `[${l.timestamp}] ${l.username} â€” ${l.action}: ${l.details}\n`;
    });
    alert(msg);
  } catch(e) { showToast("Failed to load user logs.", "error"); }
};

function bindNavigation() {
  document.querySelectorAll(".nav-item").forEach(link => {
    link.addEventListener("click", e => {
      e.preventDefault();
      switchTab(link.dataset.tab);
    });
  });
}

function switchTab(tab) {
  document.querySelectorAll(".nav-item").forEach(l => l.classList.remove("active"));
  document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
  const link = document.querySelector(`.nav-item[data-tab="${tab}"]`);
  const pane = document.getElementById(`tab-${tab}`);
  if (link) link.classList.add("active");
  if (pane) pane.classList.add("active");
  const titles = {
    "dashboard":     "Admin Dashboard",
    "publisher":     "Release & Update Publisher",
    "maintenance":   "Tweak Maintenance Kill-Switches",
    "users":         "User License & Key Management",
    "config-editor": "Raw Config & API Viewer",
  };
  document.getElementById("page-title").textContent = titles[tab] || "Dashboard";
  if (tab === "users") loadUsersData();
}

async function loadLiveData() {
  try {
    const [cfgRes, statsRes] = await Promise.all([apiFetch("/api/config"), apiFetch("/api/stats")]);
    liveConfig = await cfgRes.json();
    const stats = await statsRes.json();
    maintenanceTweaks = new Set((liveConfig.maintenance_tweaks || []).map(Number));
    updateMetrics(liveConfig, stats);
    updateDashboardPanels(liveConfig);
    updateTweakGrid();
    updateVersionPill(liveConfig.version);
    syncRawEditor(liveConfig);
    const hint = document.getElementById("current-version-hint");
    if (hint) hint.textContent = liveConfig.version;
  } catch (err) {
    console.error("Failed to fetch live data:", err);
    showToast("Could not reach API server. Is server.py running?", "error");
  }
}

function updateMetrics(config, stats) {
  setText("metric-version", `v${config.version}`);
  setText("metric-date", `Released: ${config.release_date || "â€”"}`);
  setText("metric-maintenance", `${maintenanceTweaks.size} Locked`);
  setText("metric-releases", `${stats.total_releases} Build${stats.total_releases !== 1 ? "s" : ""}`);
  const hash = config.sha256;
  setText("metric-sha256", hash ? `${hash.slice(0, 16)}...${hash.slice(-8)}` : "None Published");
}

function updateVersionPill(version) {
  document.getElementById("live-version-pill").querySelector(".pill-text").textContent = `v${version} Live`;
}

function updateDashboardPanels(config) {
  const preview = document.getElementById("dashboard-changelog-preview");
  preview.textContent = config.changelog || "No changelog available.";
  const list = document.getElementById("quick-maintenance-list");
  if (maintenanceTweaks.size === 0) {
    list.innerHTML = '<div class="empty-state">All tweaks are currently active and available to clients.</div>';
  } else {
    list.innerHTML = [...maintenanceTweaks].sort((a,b)=>a-b).map(id => {
      const tw = TWEAKS.find(t => t.id === id);
      return `<div class="quick-item">
        <span style="font-size:13px;font-weight:600;">#${id} â€” ${tw ? tw.name : "Tweak #" + id}</span>
        <span class="badge badge-amber">Under Maintenance</span>
      </div>`;
    }).join("");
  }
}

function syncRawEditor(config) {
  const ed = document.getElementById("raw-json-editor");
  if (ed && config) ed.value = JSON.stringify(config, null, 2);
}

function buildTweakGrid() {
  const grid = document.getElementById("tweaks-grid");
  grid.innerHTML = TWEAKS.map(tw => `
    <div class="tweak-card" id="tweak-card-${tw.id}">
      <div class="tweak-header">
        <div>
          <div class="tweak-title">${tw.name}</div>
          <div class="tweak-id">TWEAK #${String(tw.id).padStart(2,"0")}</div>
        </div>
      </div>
      <div class="tweak-desc">${tw.desc}</div>
      <div class="tweak-footer">
        <span class="tweak-status-label" id="status-label-${tw.id}">Active</span>
        <label class="switch">
          <input type="checkbox" id="tweak-toggle-${tw.id}" checked data-tweak-id="${tw.id}">
          <span class="slider"></span>
        </label>
      </div>
    </div>`).join("");
  TWEAKS.forEach(tw => {
    document.getElementById(`tweak-toggle-${tw.id}`).addEventListener("change", e => {
      handleTweakToggle(tw.id, e.target.checked);
    });
  });
}

function updateTweakGrid() {
  TWEAKS.forEach(tw => {
    const card   = document.getElementById(`tweak-card-${tw.id}`);
    const toggle = document.getElementById(`tweak-toggle-${tw.id}`);
    const label  = document.getElementById(`status-label-${tw.id}`);
    const locked = maintenanceTweaks.has(tw.id);
    toggle.checked = !locked;
    if (locked) {
      card.classList.add("maintenance");
      label.textContent = "Under Maintenance";
      label.style.color = "var(--color-amber)";
    } else {
      card.classList.remove("maintenance");
      label.textContent = "Active";
      label.style.color = "var(--color-green)";
    }
  });
}

async function handleTweakToggle(id, isActive) {
  isActive ? maintenanceTweaks.delete(id) : maintenanceTweaks.add(id);
  await pushMaintenanceUpdate();
  updateTweakGrid();
  if (liveConfig) updateDashboardPanels(liveConfig);
}

function bindMaintenanceButtons() {
  document.getElementById("btn-enable-all").addEventListener("click", async () => {
    maintenanceTweaks.clear();
    await pushMaintenanceUpdate();
    updateTweakGrid();
    if (liveConfig) updateDashboardPanels(liveConfig);
    showToast("All tweaks re-enabled for connected clients.");
  });
  document.getElementById("btn-lock-all").addEventListener("click", async () => {
    maintenanceTweaks = new Set(TWEAKS.map(t => t.id));
    await pushMaintenanceUpdate();
    updateTweakGrid();
    if (liveConfig) updateDashboardPanels(liveConfig);
    showToast("All tweaks locked. Clients will see UNDER MAINTENANCE.");
  });
}

async function pushMaintenanceUpdate() {
  try {
    const res  = await apiFetch("/api/maintenance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ maintenance_tweaks: [...maintenanceTweaks] }),
    });
    const data = await res.json();
    if (data.success && liveConfig) {
      liveConfig.maintenance_tweaks = data.maintenance_tweaks;
      syncRawEditor(liveConfig);
    }
    showToast("Maintenance config pushed to live clients.");
  } catch (err) {
    showToast("Failed to push maintenance update.", "error");
  }
}

function bindPublisher() {
  const dropZone  = document.getElementById("drop-zone");
  const fileInput = document.getElementById("file-input");
  const form      = document.getElementById("upload-form");
  dropZone.addEventListener("click", () => fileInput.click());
  dropZone.addEventListener("dragover",  e => { e.preventDefault(); dropZone.classList.add("dragover"); });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
  dropZone.addEventListener("drop", e => {
    e.preventDefault(); dropZone.classList.remove("dragover");
    const f = e.dataTransfer.files[0]; if (f) handleFileSelect(f);
  });
  fileInput.addEventListener("change", () => { if (fileInput.files[0]) handleFileSelect(fileInput.files[0]); });
  form.addEventListener("submit", e => { e.preventDefault(); publishUpdate(); });
}

function handleFileSelect(file) {
  if (!file.name.endsWith(".exe")) { showToast("Only .exe files are accepted.", "error"); return; }
  selectedFile = file;
  document.getElementById("selected-file-name").textContent = file.name;
  document.getElementById("selected-file-size").textContent = formatBytes(file.size);
  document.getElementById("file-details").style.display = "flex";
  document.getElementById("hash-preview-container").style.display = "block";
  const badge = document.getElementById("hash-status-badge");
  badge.textContent = "Computing..."; badge.className = "badge badge-amber";
  document.getElementById("calculated-sha256").textContent = "Computing SHA-256...";
  const reader = new FileReader();
  reader.onload = async evt => {
    try {
      const buf  = await crypto.subtle.digest("SHA-256", evt.target.result);
      clientSideSHA = Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
      document.getElementById("calculated-sha256").textContent = clientSideSHA;
      badge.textContent = "Verified"; badge.className = "badge badge-green";
    } catch(e) {
      document.getElementById("calculated-sha256").textContent = "Hash error.";
    }
  };
  reader.readAsArrayBuffer(file);
}

async function publishUpdate() {
  if (!selectedFile) { showToast("Please select a .exe file first.", "error"); return; }
  const version   = document.getElementById("version-input").value.trim();
  const changelog = document.getElementById("changelog-input").value.trim();
  if (!version)   { showToast("Version is required.", "error"); return; }
  if (!changelog) { showToast("Changelog notes are required.", "error"); return; }
  const btn = document.getElementById("btn-publish");
  btn.disabled = true; btn.innerHTML = '<span class="btn-icon">...</span> Publishing...';
  const fd = new FormData();
  fd.append("file", selectedFile); fd.append("version", version); fd.append("changelog", changelog);
  try {
    const res  = await apiFetch("/api/publish-update", { method: "POST", body: fd });
    const data = await res.json();
    if (data.success) {
      liveConfig = data.config;
      maintenanceTweaks = new Set((liveConfig.maintenance_tweaks || []).map(Number));
      updateVersionPill(liveConfig.version);
      syncRawEditor(liveConfig);
      const hint = document.getElementById("current-version-hint");
      if (hint) hint.textContent = liveConfig.version;
      showToast(`v${version} published! SHA-256 verified.`);
    } else { showToast(`Publish failed: ${data.error}`, "error"); }
  } catch(err) { showToast("Network error during publish.", "error"); }
  finally { btn.disabled = false; btn.innerHTML = '<span class="btn-icon">ðŸš€</span> Publish & Broadcast Update'; }
}

function bindConfigEditor() {
  document.getElementById("btn-save-raw").addEventListener("click", async () => {
    const ed = document.getElementById("raw-json-editor");
    let parsed;
    try { parsed = JSON.parse(ed.value); }
    catch(e) { showToast("Invalid JSON â€” fix syntax errors before saving.", "error"); return; }
    try {
      const res  = await apiFetch("/api/save-config", {
        method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(parsed)
      });
      const data = await res.json();
      if (data.success) {
        liveConfig = data.config;
        maintenanceTweaks = new Set((liveConfig.maintenance_tweaks || []).map(Number));
        updateTweakGrid(); updateVersionPill(liveConfig.version);
        showToast("Raw config saved and applied to live API.");
      } else { showToast(`Save failed: ${data.error}`, "error"); }
    } catch(e) { showToast("Network error when saving config.", "error"); }
  });
}

window.insertBullet = function(prefix) {
  const ta = document.getElementById("changelog-input");
  const s = ta.selectionStart, e = ta.selectionEnd;
  ta.value = ta.value.substring(0,s) + prefix + ta.value.substring(e);
  ta.selectionStart = ta.selectionEnd = s + prefix.length; ta.focus();
};
window.insertTemplate = function() {
  document.getElementById("changelog-input").value =
    "- Performance improvements\n- Stability fixes\n- Reduced CPU overhead\n- Ultra-low latency engine update";
};
window.switchTab = switchTab;

function setText(id, text) { const el = document.getElementById(id); if (el) el.textContent = text; }
function formatBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1048576).toFixed(2)} MB`;
}
let _toastTimer = null;
function showToast(msg, type="success") {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.style.borderColor = type === "error" ? "var(--color-red)" : "var(--color-cyan)";
  t.classList.add("show");
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove("show"), 3800);
}
