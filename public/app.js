/* Pulse Control Panel - production build (source in /frontend) */
"use strict";

const ADMIN_TOKEN_KEY = "pulse_admin_token";

function getAdminToken() {
 try {
 return sessionStorage.getItem(ADMIN_TOKEN_KEY) || "";
 } catch (_) {
 return "";
 }
}

function setAdminToken(token) {
 try {
 if (token) sessionStorage.setItem(ADMIN_TOKEN_KEY, token);
 else sessionStorage.removeItem(ADMIN_TOKEN_KEY);
 } catch (_) { }
}

async function apiFetch(url, options = {}) {
 const opts = { credentials: "include", ...options };
 opts.headers = { ...(options.headers || {}) };
 const token = getAdminToken();
 if (token && !opts.headers.Authorization && !opts.headers.authorization) {
 opts.headers.Authorization = `Bearer ${token}`;
 }
 const res = await fetch(url, opts);
 if (res.status === 401 && !String(url).includes("/api/admin/login") && !String(url).includes("/api/admin/session")) {
 setAdminToken("");
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
 { id: 1, name: "1:1 Raw Mouse Input & Linear Curve", desc: "Disables pointer acceleration and flattens response curve for true 1:1 pixel precision." },
 { id: 2, name: "High-Speed Keyboard Latency (0ms Delay)", desc: "Sets 0 repeat delay and max 31 repeat rate for instant mechanical response." },
 { id: 3, name: "MMCSS Gaming Thread & GPU Priority 8", desc: "Prioritizes foreground game threads and GPU processing inside the Multimedia Scheduler." },
 { id: 4, name: "Hardware GPU Scheduling (HAGS)", desc: "Reduces GPU latency and frees CPU scheduling overhead via hardware scheduler coprocessor." },
 { id: 5, name: "Disable Game DVR & Background Capture", desc: "Stops background video capture buffer and eliminates 1% low FPS micro-stuttering." },
 { id: 6, name: "Win32 CPU Quantum Priority (0x26 Boost)", desc: "Allocates maximum CPU time-slices and priority to the active foreground game." },
 { id: 7, name: "MenuShowDelay to 0ms (Instant UI)", desc: "Removes Windows shell animation wait-time and makes context menus open instantly." },
 { id: 8, name: "Disable Network Throttling Index", desc: "Stops Windows from throttling network packets during gaming or multimedia playback." },
 { id: 9, name: "Set SystemResponsiveness to 0%", desc: "Gives active game 100% network & CPU priority instead of reserving 20% for background tasks." },
 { id: 10, name: "0.5ms Timer Resolution Enforcer", desc: "Forces Windows kernel timer resolution to 0.5ms for lowest frame variance and jitter." },
 { id: 11, name: "GPU MSI Mode (Message Signaled Interrupts)", desc: "Configures GPU PCIe controller to high-priority MSI mode to slash DPC latency." },
 { id: 12, name: "Disable CPU Core Parking (100% Readiness)", desc: "Unparks all physical and logical CPU cores to ensure maximum clock speed readiness." },
 { id: 13, name: "Disable MPO (Multiplane Overlay Stutter Fix)", desc: "Disables DWM Multiplane Overlays to fix windowed gaming stutter and screen flickers." },
 { id: 14, name: "Disable Windows Delivery Optimization", desc: "Stops Windows from using your upload bandwidth to seed updates to other PCs." },
 { id: 15, name: "Disable SysMain / SuperFetch Disk Thrashing", desc: "Eliminates unnecessary background caching and disk I/O on NVMe SSD drives." },
 { id: 16, name: "Disable DiagTrack Telemetry & Logging", desc: "Disables telemetry event tracing and background diagnostic diagnostics." },
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
 setAdminToken("");
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
 btn.textContent = "Signing in...";
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
 if (data.token) setAdminToken(data.token);
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
 setAdminToken("");
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
 bindStorageAlert();
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
 const attrKey = escapeAttr(k.key);
 const attrHwid = escapeAttr(k.bound_hwid || "");
 const attrIp = escapeAttr(k.bound_ip || "");
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
 <td style="padding:10px;text-align:right;" class="key-actions">
 <button type="button" class="btn btn-secondary btn-small" data-action="add-time" data-key="${attrKey}">+30D</button>
 <button type="button" class="btn btn-secondary btn-small" data-action="toggle-freeze" data-key="${attrKey}" data-freeze="${k.is_frozen ? "0" : "1"}">${k.is_frozen ? "Unfreeze" : "Freeze"}</button>
 <button type="button" class="btn btn-secondary btn-small" title="Unfreeze key if frozen and reset freeze quota to 0" data-action="reset-freezes" data-key="${attrKey}">Reset Freezes</button>
 <button type="button" class="btn btn-secondary btn-small" data-action="revoke" data-key="${attrKey}">Revoke</button>
 ${k.bound_hwid ? `<button type="button" class="btn btn-secondary btn-small" style="color:#ef4444;" data-action="ban" data-key="${attrKey}" data-hwid="${attrHwid}" data-ip="${attrIp}">Ban</button>` : ""}
 <button type="button" class="btn btn-secondary btn-small" style="color:#f87171;" data-action="delete-key" data-key="${attrKey}">Delete</button>
 <button type="button" class="btn btn-primary btn-small" data-action="view-logs" data-key="${attrKey}">Logs</button>
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
 if (btn && !btn.dataset.bound) {
 btn.dataset.bound = "1";
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
 } catch (err) { showToast("Network error during key generation.", "error"); }
 });
 }

 const container = document.getElementById("users-table-container");
 if (container && !container.dataset.actionsBound) {
 container.dataset.actionsBound = "1";
 container.addEventListener("click", (e) => {
 const btnEl = e.target.closest("[data-action]");
 if (!btnEl || !container.contains(btnEl)) return;
 const action = btnEl.getAttribute("data-action");
 const key = btnEl.getAttribute("data-key") || "";
 if (action === "add-time") adminAddTime(key);
 else if (action === "toggle-freeze") adminToggleFreeze(key, btnEl.getAttribute("data-freeze") === "1");
 else if (action === "reset-freezes") adminResetFreezes(key);
 else if (action === "revoke") adminRevoke(key);
 else if (action === "ban") adminBan(key, btnEl.getAttribute("data-hwid") || "", btnEl.getAttribute("data-ip") || "");
 else if (action === "delete-key") adminDeleteKey(key);
 else if (action === "view-logs") adminViewLogs(key);
 });
 }
}

async function adminAddTime(key) {
 try {
 const res = await apiFetch("/api/admin/add-time", {
 method: "POST", headers: {"Content-Type": "application/json"},
 body: JSON.stringify({ key, days: 30 })
 });
 const data = await res.json();
 if (data.success) { showToast(`Added 30 days to ${key}`); loadUsersData(); }
 } catch (e) { showToast("Action failed.", "error"); }
}

async function adminToggleFreeze(key, freeze) {
 try {
 const res = await apiFetch("/api/admin/freeze-key", {
 method: "POST", headers: {"Content-Type": "application/json"},
 body: JSON.stringify({ key, freeze })
 });
 const data = await res.json();
 if (data.success) { showToast(`Key ${key} ${freeze ? "Frozen" : "Unfrozen"}`); loadUsersData(); }
 } catch (e) { showToast("Action failed.", "error"); }
}

async function adminResetFreezes(key) {
 if (!confirm(`Reset freeze quota for ${key} and unfreeze it if currently frozen?`)) return;
 try {
 const res = await apiFetch("/api/admin/reset-freezes", {
 method: "POST", headers: {"Content-Type": "application/json"},
 body: JSON.stringify({ key })
 });
 const data = await res.json();
 if (data.success) { showToast(`Reset freezes & unfroze ${key}`); loadUsersData(); }
 else { showToast(data.error || "Failed to reset freezes.", "error"); }
 } catch (e) { showToast("Action failed.", "error"); }
}

async function adminDeleteKey(key) {
 if (!confirm(`Are you sure you want to permanently DELETE key ${key} from the server? This cannot be undone.`)) return;
 try {
 const res = await apiFetch("/api/admin/delete-key", {
 method: "POST", headers: {"Content-Type": "application/json"},
 body: JSON.stringify({ key })
 });
 const data = await res.json();
 if (data.success) { showToast(`Deleted key ${key}`); loadUsersData(); }
 else { showToast(data.error || "Failed to delete key.", "error"); }
 } catch (e) { showToast("Action failed.", "error"); }
}

async function adminRevoke(key) {
 if (!confirm(`Are you sure you want to revoke key ${key}?`)) return;
 try {
 const res = await apiFetch("/api/admin/revoke-key", {
 method: "POST", headers: {"Content-Type": "application/json"},
 body: JSON.stringify({ key })
 });
 const data = await res.json();
 if (data.success) { showToast(`Revoked key ${key}`); loadUsersData(); }
 } catch (e) { showToast("Action failed.", "error"); }
}

async function adminBan(key, hwid, ip) {
 if (!confirm(`Are you sure you want to BAN HWID ${hwid}? This device will be safely self-cleaned and blocked.`)) return;
 try {
 const res = await apiFetch("/api/admin/ban-user", {
 method: "POST", headers: {"Content-Type": "application/json"},
 body: JSON.stringify({ key, hwid, ip })
 });
 const data = await res.json();
 if (data.success) { showToast(`Banned HWID ${hwid}`); loadUsersData(); }
 } catch (e) { showToast("Action failed.", "error"); }
}

async function adminViewLogs(key) {
 try {
 const res = await apiFetch(`/api/admin/user-logs?key=${encodeURIComponent(key)}`);
 const logs = await res.json();
 if (!logs || logs.length === 0) {
 alert(`No activity logs recorded for key ${key} yet.`);
 return;
 }
 let msg = `Activity Timeline Log for ${key}:\n\n`;
 logs.forEach(l => {
 msg += `[${l.timestamp}] ${l.username} - ${l.action}: ${l.details}\n`;
 });
 alert(msg);
 } catch (e) { showToast("Failed to load user logs.", "error"); }
}

function bindNavigation() {
 document.querySelectorAll(".nav-item").forEach(link => {
 link.addEventListener("click", e => {
 e.preventDefault();
 switchTab(link.dataset.tab);
 });
 });

 // CSP-safe replacements for former inline onclick handlers in HTML
 document.querySelectorAll("[data-action='switch-tab']").forEach(btn => {
 if (btn.dataset.bound) return;
 btn.dataset.bound = "1";
 btn.addEventListener("click", () => switchTab(btn.getAttribute("data-tab") || "dashboard"));
 });
 document.querySelectorAll("[data-action='insert-bullet']").forEach(btn => {
 if (btn.dataset.bound) return;
 btn.dataset.bound = "1";
 btn.addEventListener("click", () => insertBullet(btn.getAttribute("data-prefix") || "- "));
 });
 document.querySelectorAll("[data-action='insert-section']").forEach(btn => {
 if (btn.dataset.bound) return;
 btn.dataset.bound = "1";
 btn.addEventListener("click", () => insertSection(btn.getAttribute("data-section") || "Added"));
 });
 document.querySelectorAll("[data-action='insert-template']").forEach(btn => {
 if (btn.dataset.bound) return;
 btn.dataset.bound = "1";
 btn.addEventListener("click", () => insertTemplate());
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
 "dashboard": "Admin Dashboard",
 "publisher": "Release & Update Publisher",
 "maintenance": "Tweak Maintenance Kill-Switches",
 "users": "User License & Key Management",
 "config-editor": "Raw Config & API Viewer",
 };
 document.getElementById("page-title").textContent = titles[tab] || "Dashboard";
 if (tab === "users") loadUsersData();
}

async function loadLiveData() {
 try {
 const [cfgRes, statsRes, relRes] = await Promise.all([
 apiFetch("/api/config"),
 apiFetch("/api/stats"),
 apiFetch("/api/admin/releases"),
 ]);
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

 if (relRes.ok) {
 const relData = await relRes.json();
 updatePublisherPanels(relData.current || liveConfig, relData.releases || [], relData.storage || stats.storage);
 } else if (stats.storage) {
 updatePublisherPanels(liveConfig, [], stats.storage);
 }
 } catch (err) {
 console.error("Failed to fetch live data:", err);
 showToast("Could not reach API server. Is server.py running?", "error");
 }
}

function updateMetrics(config, stats) {
 setText("metric-version", `v${config.version}`);
 setText("metric-date", `Released: ${config.release_date || "-"}`);
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
 preview.textContent = sanitizeChangelogClient(config.changelog || "") || "No changelog available.";
 const list = document.getElementById("quick-maintenance-list");
 if (maintenanceTweaks.size === 0) {
 list.innerHTML = '<div class="empty-state">All tweaks are currently active and available to clients.</div>';
 } else {
 list.innerHTML = [...maintenanceTweaks].sort((a,b)=>a-b).map(id => {
 const tw = TWEAKS.find(t => t.id === id);
 return `<div class="quick-item">
 <span style="font-size:13px;font-weight:600;">#${id} - ${tw ? tw.name : "Tweak #" + id}</span>
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
 const card = document.getElementById(`tweak-card-${tw.id}`);
 const toggle = document.getElementById(`tweak-toggle-${tw.id}`);
 const label = document.getElementById(`status-label-${tw.id}`);
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
 const res = await apiFetch("/api/maintenance", {
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
 const dropZone = document.getElementById("drop-zone");
 const fileInput = document.getElementById("file-input");
 const form = document.getElementById("upload-form");
 if (!dropZone || !fileInput || !form) return;
 if (form.dataset.bound) return;
 form.dataset.bound = "1";

 dropZone.addEventListener("click", () => fileInput.click());
 dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("dragover"); });
 dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
 dropZone.addEventListener("drop", e => {
 e.preventDefault(); dropZone.classList.remove("dragover");
 const f = e.dataTransfer.files[0]; if (f) handleFileSelect(f);
 });
 fileInput.addEventListener("change", () => { if (fileInput.files[0]) handleFileSelect(fileInput.files[0]); });
 form.addEventListener("submit", e => { e.preventDefault(); publishUpdate(); });

 const refreshBtn = document.getElementById("btn-refresh-releases");
 if (refreshBtn) refreshBtn.addEventListener("click", () => loadLiveData());
 const purgeBtn = document.getElementById("btn-purge-keep3");
 if (purgeBtn) purgeBtn.addEventListener("click", () => purgeReleases(3));
 const saveStorageBtn = document.getElementById("btn-save-storage-settings");
 if (saveStorageBtn && !saveStorageBtn.dataset.bound) {
 saveStorageBtn.dataset.bound = "1";
 saveStorageBtn.addEventListener("click", saveStorageSettings);
 }
 const toggleStorageBtn = document.getElementById("btn-toggle-storage-settings");
 if (toggleStorageBtn && !toggleStorageBtn.dataset.bound) {
 toggleStorageBtn.dataset.bound = "1";
 toggleStorageBtn.addEventListener("click", () => setStorageSettingsExpanded(!isStorageSettingsExpanded()));
 }
 const editStorageBtn = document.getElementById("btn-edit-storage-settings");
 if (editStorageBtn && !editStorageBtn.dataset.bound) {
 editStorageBtn.dataset.bound = "1";
 editStorageBtn.addEventListener("click", () => setStorageSettingsExpanded(true));
 }
}

function isStorageSettingsExpanded() {
 const body = document.getElementById("storage-settings-body");
 return !!(body && !body.hidden);
}

function setStorageSettingsExpanded(expanded) {
 const body = document.getElementById("storage-settings-body");
 const summary = document.getElementById("storage-settings-summary");
 const chevron = document.getElementById("storage-settings-chevron");
 const toggle = document.getElementById("btn-toggle-storage-settings");
 if (body) body.hidden = !expanded;
 if (summary) summary.hidden = expanded;
 if (chevron) chevron.textContent = expanded ? "v" : "";
 if (toggle) toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
}

function refreshStorageSettingsSummary(storage) {
 const el = document.getElementById("storage-settings-summary-text");
 if (!el || !storage) return;
 const settings = storage.settings || {};
 const cap = settings.soft_cap_mb ?? storage.soft_cap_mb ?? 500;
 const warn = settings.warn_mb ?? storage.warn_mb ?? 400;
 const crit = settings.crit_mb ?? storage.crit_mb ?? 480;
 el.textContent = `${cap} MB bucket - warn ${warn} MB - critical ${crit} MB`;
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
 const buf = await crypto.subtle.digest("SHA-256", evt.target.result);
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
 const version = document.getElementById("version-input").value.trim();
 const changelog = sanitizeChangelogClient(document.getElementById("changelog-input").value);
 const mandatory = document.getElementById("mandatory-input")?.value || "true";
 if (!version) { showToast("Version is required.", "error"); return; }
 if (!changelog) { showToast("Changelog notes are required.", "error"); return; }
 if (!clientSideSHA) { showToast("Wait for SHA-256 to finish computing.", "error"); return; }
 // Reflect sanitized text back into the textarea so authors see what ships
 const ta = document.getElementById("changelog-input");
 if (ta) { ta.value = changelog; refreshChangelogPreview(); }
 const btn = document.getElementById("btn-publish");
 btn.disabled = true; btn.innerHTML = '<span class="btn-icon">...</span> Publishing...';

 try {
 const prepRes = await apiFetch("/api/admin/prepare-upload", {
 method: "POST",
 headers: { "Content-Type": "application/json" },
 body: JSON.stringify({ version }),
 });
 const prep = await prepRes.json();
 if (!prepRes.ok || !prep.success) {
 throw new Error(prep.error || "Could not prepare upload");
 }

 let data;
 if (prep.mode === "supabase" && prep.upload_url) {
 btn.innerHTML = '<span class="btn-icon">...</span> Uploading to storage...';
 const putRes = await fetch(prep.upload_url, {
 method: "PUT",
 headers: {
 "Content-Type": "application/octet-stream",
 "x-upsert": "true",
 },
 body: selectedFile,
 });
 if (!putRes.ok) {
 const errText = await putRes.text().catch(() => "");
 throw new Error(`Storage upload failed (${putRes.status}). Check Supabase bucket CORS. ${errText.slice(0, 120)}`);
 }
 btn.innerHTML = '<span class="btn-icon">...</span> Finalizing release...';
 const finRes = await apiFetch("/api/publish-update", {
 method: "POST",
 headers: { "Content-Type": "application/json" },
 body: JSON.stringify({
 version,
 changelog,
 mandatory,
 sha256: clientSideSHA,
 file_size: selectedFile.size,
 file_name: prep.file_name,
 download_url: prep.public_url,
 }),
 });
 data = await finRes.json();
 if (!finRes.ok || !data.success) throw new Error(data.error || "Publish finalize failed");
 } else {
 const fd = new FormData();
 fd.append("file", selectedFile);
 fd.append("version", version);
 fd.append("changelog", changelog);
 fd.append("mandatory", mandatory);
 const res = await apiFetch("/api/publish-update", { method: "POST", body: fd });
 data = await res.json();
 if (!res.ok || !data.success) throw new Error(data.error || "Publish failed");
 }

 liveConfig = data.config;
 maintenanceTweaks = new Set((liveConfig.maintenance_tweaks || []).map(Number));
 updateVersionPill(liveConfig.version);
 syncRawEditor(liveConfig);
 updatePublisherPanels(liveConfig, data.releases || [], data.storage);
 const hint = document.getElementById("current-version-hint");
 if (hint) hint.textContent = liveConfig.version;
 showToast(`v${version} published! SHA-256 verified.`);
 selectedFile = null;
 document.getElementById("file-details").style.display = "none";
 document.getElementById("hash-preview-container").style.display = "none";
 document.getElementById("file-input").value = "";
 clientSideSHA = "";
 } catch (err) {
 if (err && err.storage) updateStorageUI(err.storage);
 showToast(String(err.message || err || "Publish failed"), "error");
 } finally {
 btn.disabled = false;
 btn.innerHTML = '<span class="btn-icon"></span> Publish & Broadcast Update';
 }
}

function updatePublisherPanels(config, releases, storage) {
 if (config) {
 setText("pub-live-version", config.version ? `v${config.version}` : "-");
 setText("pub-live-date", config.release_date || "-");
 setText("pub-live-size", config.file_size ? formatBytes(config.file_size) : "-");
 setText("pub-live-mandatory", config.mandatory === false ? "Optional" : "Mandatory");
 const sha = config.sha256 || "";
 setText("pub-live-sha", sha ? sha : "-");
 setText("pub-live-url", config.download_url || "-");
 const cl = document.getElementById("pub-live-changelog");
 if (cl) cl.textContent = sanitizeChangelogClient(config.changelog || "") || "No release published yet.";
 }
 renderReleasesTable(releases || [], config?.version);
 if (storage) updateStorageUI(storage);
}

function renderReleasesTable(releases, liveVersion) {
 const tbody = document.getElementById("releases-tbody");
 if (!tbody) return;
 if (!releases.length) {
 tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No releases yet - publish your first build above.</td></tr>';
 return;
 }
 tbody.innerHTML = releases.map(r => {
 const ver = r.version || "";
 const isLive = !!(r.is_active || ver === liveVersion);
 const sha = r.sha256 || "";
 const shaShort = sha ? `${sha.slice(0, 10)}...${sha.slice(-6)}` : "-";
 const size = r.file_size ? formatBytes(r.file_size) : "-";
 const status = isLive
 ? '<span class="badge badge-green">LIVE</span>'
 : '<span class="badge badge-muted">Archived</span>';
 const actions = isLive
 ? '<span class="muted-action">Current channel</span>'
 : `<div class="row-actions">
 <button type="button" class="btn btn-tiny btn-primary" data-rollback="${escapeAttr(ver)}">Rollback</button>
 <button type="button" class="btn btn-tiny btn-danger" data-delete-release="${escapeAttr(ver)}">Delete</button>
 </div>`;
 return `<tr>
 <td><strong>v${escapeHtml(ver)}</strong></td>
 <td>${escapeHtml(r.release_date || "-")}</td>
 <td>${escapeHtml(size)}</td>
 <td><code class="sha-cell" title="${escapeAttr(sha)}">${escapeHtml(shaShort)}</code></td>
 <td>${status}</td>
 <td>${actions}</td>
 </tr>`;
 }).join("");

 tbody.querySelectorAll("[data-rollback]").forEach(btn => {
 btn.addEventListener("click", () => rollbackRelease(btn.getAttribute("data-rollback")));
 });
 tbody.querySelectorAll("[data-delete-release]").forEach(btn => {
 btn.addEventListener("click", () => deleteRelease(btn.getAttribute("data-delete-release")));
 });
}

function updateStorageUI(storage) {
 if (!storage) return;
 const pct = Math.min(100, Number(storage.percent_used) || 0);
 const level = storage.level || "ok";

 setText("storage-usage-human", storage.total_human || formatBytes(storage.total_bytes || 0));
 setText("storage-usage-cap", `of ${storage.soft_cap_human || "500 MB"}`);
 setText("storage-file-count", `${storage.file_count || 0} build${(storage.file_count || 0) === 1 ? "" : "s"}`);
 setText("storage-percent", `${pct}% used`);

 const fill = document.getElementById("storage-bar-fill");
 if (fill) {
 fill.style.width = `${pct}%`;
 fill.dataset.level = level;
 }

 const badge = document.getElementById("storage-level-badge");
 if (badge) {
 badge.textContent = level === "critical" ? "CRITICAL" : level === "warning" ? "WARNING" : "OK";
 badge.className = "badge " + (level === "critical" ? "badge-red" : level === "warning" ? "badge-amber" : "badge-green");
 }

 const hint = document.getElementById("storage-hint-text");
 if (hint) {
 hint.textContent = storage.message || "Keep a few prior builds for rollback. Purge when the meter turns amber.";
 hint.dataset.level = level;
 }

 const settings = storage.settings || {};
 const setVal = (id, val) => {
 const el = document.getElementById(id);
 if (el && document.activeElement !== el) el.value = val;
 };
 setVal("storage-cap-mb", settings.soft_cap_mb ?? storage.soft_cap_mb ?? 500);
 setVal("storage-warn-mb", settings.warn_mb ?? storage.warn_mb ?? 400);
 setVal("storage-crit-mb", settings.crit_mb ?? storage.crit_mb ?? 480);
 setVal("storage-warn-count", settings.warn_count ?? storage.warn_count ?? 8);
 setVal("storage-crit-count", settings.crit_count ?? storage.crit_count ?? 12);
 refreshStorageSettingsSummary(storage);

 updateStorageAlertBanner(storage);
}

async function saveStorageSettings() {
 const soft = Number(document.getElementById("storage-cap-mb")?.value);
 const warn = Number(document.getElementById("storage-warn-mb")?.value);
 const crit = Number(document.getElementById("storage-crit-mb")?.value);
 const warnCount = Number(document.getElementById("storage-warn-count")?.value);
 const critCount = Number(document.getElementById("storage-crit-count")?.value);
 if (![soft, warn, crit, warnCount, critCount].every(n => Number.isFinite(n) && n > 0)) {
 showToast("Enter valid positive numbers for all storage fields.", "error");
 return;
 }
 if (warn > soft || crit > soft) {
 showToast("Warn/Critical MB must be less than or equal to bucket size.", "error");
 return;
 }
 try {
 const res = await apiFetch("/api/admin/storage-settings", {
 method: "POST",
 headers: { "Content-Type": "application/json" },
 body: JSON.stringify({
 soft_cap_mb: soft,
 warn_mb: warn,
 crit_mb: crit,
 warn_count: warnCount,
 crit_count: critCount,
 }),
 });
 const data = await res.json();
 if (!res.ok || !data.success) {
 showToast(data.error || "Could not save storage settings", "error");
 return;
 }
 _storageDismissedLevel = null;
 updateStorageUI(data.storage);
 refreshStorageSettingsSummary(data.storage);
 setStorageSettingsExpanded(false);
 showToast(`Bucket capacity set to ${soft} MB.`);
 } catch (e) {
 showToast("Network error saving storage settings.", "error");
 }
}

let _storageDismissedLevel = null;

function updateStorageAlertBanner(storage) {
 const banner = document.getElementById("storage-alert-banner");
 if (!banner) return;
 const level = storage.level || "ok";
 if (level === "ok") {
 banner.hidden = true;
 document.body.classList.remove("has-storage-alert");
 return;
 }
 if (_storageDismissedLevel === level) return;

 banner.hidden = false;
 banner.dataset.level = level;
 document.body.classList.add("has-storage-alert");

 setText("storage-alert-title", level === "critical" ? "Release storage almost full" : "Release storage filling up");
 setText("storage-alert-message", storage.message || "Past builds are filling the releases bucket.");
 const pct = Math.min(100, Number(storage.percent_used) || 0);
 const meterFill = document.getElementById("storage-alert-meter-fill");
 if (meterFill) {
 meterFill.style.width = `${pct}%`;
 meterFill.dataset.level = level;
 }
 setText("storage-alert-meter-label", `${pct}%`);
}

function bindStorageAlert() {
 const gotoBtn = document.getElementById("btn-storage-goto");
 const purgeBtn = document.getElementById("btn-storage-purge");
 const dismissBtn = document.getElementById("btn-storage-dismiss");
 if (gotoBtn && !gotoBtn.dataset.bound) {
 gotoBtn.dataset.bound = "1";
 gotoBtn.addEventListener("click", () => {
 switchTab("publisher");
 document.getElementById("tab-publisher")?.scrollIntoView({ behavior: "smooth", block: "start" });
 });
 }
 if (purgeBtn && !purgeBtn.dataset.bound) {
 purgeBtn.dataset.bound = "1";
 purgeBtn.addEventListener("click", () => purgeReleases(3));
 }
 if (dismissBtn && !dismissBtn.dataset.bound) {
 dismissBtn.dataset.bound = "1";
 dismissBtn.addEventListener("click", () => {
 const banner = document.getElementById("storage-alert-banner");
 _storageDismissedLevel = banner?.dataset.level || "warning";
 banner.hidden = true;
 document.body.classList.remove("has-storage-alert");
 });
 }
}

async function rollbackRelease(version) {
 if (!version) return;
 if (!confirm(`Roll live channel back to v${version}? All clients will be told this is the current version.`)) return;
 try {
 const res = await apiFetch("/api/admin/rollback", {
 method: "POST",
 headers: { "Content-Type": "application/json" },
 body: JSON.stringify({ version }),
 });
 const data = await res.json();
 if (!res.ok || !data.success) {
 showToast(data.error || "Rollback failed", "error");
 return;
 }
 liveConfig = data.config;
 updateVersionPill(liveConfig.version);
 syncRawEditor(liveConfig);
 updatePublisherPanels(liveConfig, data.releases || [], data.storage);
 showToast(`Rolled back to v${version}. Clients will pick this up on next check.`);
 } catch (e) {
 showToast("Network error during rollback.", "error");
 }
}

async function deleteRelease(version) {
 if (!version) return;
 if (!confirm(`Delete archived build v${version} and free its storage?`)) return;
 try {
 const res = await apiFetch("/api/admin/delete-release", {
 method: "POST",
 headers: { "Content-Type": "application/json" },
 body: JSON.stringify({ version }),
 });
 const data = await res.json();
 if (!res.ok || !data.success) {
 showToast(data.error || "Delete failed", "error");
 return;
 }
 _storageDismissedLevel = null;
 updatePublisherPanels(liveConfig, data.releases || [], data.storage);
 showToast(`Deleted v${version}.`);
 } catch (e) {
 showToast("Network error when deleting release.", "error");
 }
}

async function purgeReleases(keep) {
 if (!confirm(`Delete older builds and keep only the newest ${keep}? The live version is always kept.`)) return;
 try {
 const res = await apiFetch("/api/admin/purge-releases", {
 method: "POST",
 headers: { "Content-Type": "application/json" },
 body: JSON.stringify({ keep }),
 });
 const data = await res.json();
 if (!res.ok || !data.success) {
 showToast(data.error || "Purge failed", "error");
 return;
 }
 _storageDismissedLevel = null;
 updatePublisherPanels(liveConfig, data.releases || [], data.storage);
 const removed = (data.removed || []).length;
 showToast(removed ? `Purged ${removed} old build(s).` : "Nothing to purge - already within keep limit.");
 } catch (e) {
 showToast("Network error during purge.", "error");
 }
}

function escapeHtml(s) {
 return String(s ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
}
function escapeAttr(s) {
 return escapeHtml(s).replace(/`/g, "&#96;");
}

function bindConfigEditor() {
 document.getElementById("btn-save-raw").addEventListener("click", async () => {
 const ed = document.getElementById("raw-json-editor");
 let parsed;
 try { parsed = JSON.parse(ed.value); }
 catch(e) { showToast("Invalid JSON - fix syntax errors before saving.", "error"); return; }
 try {
 const res = await apiFetch("/api/save-config", {
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

function insertBullet(prefix) {
 const ta = document.getElementById("changelog-input");
 if (!ta) return;
 const s = ta.selectionStart, e = ta.selectionEnd;
 const insert = prefix || "- ";
 ta.value = ta.value.substring(0, s) + insert + ta.value.substring(e);
 ta.selectionStart = ta.selectionEnd = s + insert.length;
 ta.focus();
 refreshChangelogPreview();
}

function insertSection(name) {
 const ta = document.getElementById("changelog-input");
 if (!ta) return;
 const block = (ta.value && !ta.value.endsWith("\n") ? "\n" : "") + name + "\n- ";
 const s = ta.selectionStart, e = ta.selectionEnd;
 ta.value = ta.value.substring(0, s) + block + ta.value.substring(e);
 ta.selectionStart = ta.selectionEnd = s + block.length;
 ta.focus();
 refreshChangelogPreview();
}

const CHANGELOG_TEMPLATES = {
 patch: `Pulse Hardware Suite - Patch Notes

Added
-

Improved
-

Fixed
- `,
 initial: `Pulse Hardware Suite - Initial Release

- Live CPU / RAM monitoring with hardware specs
- Game Booster, Network Optimizer, and Windows Tweaks
- Bloat Remover, Deep Cleaner, and Driver Manager
- License auth with freeze / unfreeze support
- Cloud auto-update from the control panel`,
 hotfix: `Hotfix

Fixed
- Critical crash / stability issue
-

Notes
- Recommended for all users`,
 performance: `Performance Update

Improved
- Reduced CPU overhead while idle
- Faster metrics sampling
- Smoother UI animations

Fixed
- Edge-case timer / hitch issues`,
 feature: `Feature Drop

Added
- New module / workflow
-

Improved
- Existing flows polished for clarity

Fixed
- Minor UI / hitbox issues`,
 security: `Security Update

Fixed
- Auth / session hardening
- Input validation improvements

Improved
- Safer update verification path

Notes
- Mandatory update recommended`,
 maintenance: `Maintenance / Polish

Improved
- UI wording and layout cleanup
- Toast / modal consistency

Fixed
- Assorted small bugs reported this week`,
 ui: `UI / Visual Refresh

Improved
- Cleaner release notes presentation
- Theme / typography polish
- Better spacing on Settings and Dashboard

Fixed
- Overflow / clipping on dense text panels`,
 monitoring: `Monitoring Update

Added
- Disk Health scan with SMART / media status
- Pulse Score on Dashboard with baseline capture

Improved
- Hardware telemetry readability
- Drive temperature / power-on hour display

Fixed
- Edge cases in hardware inventory`,
 optimizer: `Optimizer Suite Update

Improved
- Game Booster apply / restore flow
- Network Optimizer defaults
- Windows Tweaks clarity and recommendations

Fixed
- Tweak apply failures on locked policies
- Cleaner / debloat edge cases`,
 auth: `Auth / Licensing Update

Improved
- Login / key paste formatting
- Freeze / unfreeze messaging
- Session reliability

Fixed
- Auth status edge cases
- Hitbox / input focus issues on the login screen`,
 updater: `Updater / Cloud Channel

Improved
- Cleaner release notes rendering in-app
- Safer SHA-256 verification messaging
- Control panel publish templates

Fixed
- Changelog overflow / garbled characters
- Long patch note wrapping in the update modal`
};

function sanitizeChangelogClient(raw) {
 let s = String(raw || "");
 s = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
 // Strip emoji / dingbats
 s = s.replace(/[\u{1F300}-\u{1FAFF}]/gu, "");
 s = s.replace(/[\u2600-\u27BF]/g, "");
 // Markdown headings / emphasis
 s = s.replace(/^#{1,6}\s*/gm, "");
 s = s.replace(/[*_`]+/g, "");

 s = s.replace(/^[ \t]*[-\u2022\u25CF\u25A0\u25E6\u00B7]\s*/gm, "- ");
 s = s.replace(/[\u2013\u2014]/g, "-");
 s = s.replace(/[\u201C\u201D]/g, '"').replace(/[\u2018\u2019]/g, "'");

 s = Array.from(s).filter(ch => ch === "\n" || ch === "\t" || ch.charCodeAt(0) >= 32).join("");
 s = s.replace(/\n{3,}/g, "\n\n");
 if (s.length > 4000) s = s.slice(0, 4000).replace(/\s+$/, "") + "\n...";
 return s.trim();
}

function refreshChangelogPreview() {
 const ta = document.getElementById("changelog-input");
 const preview = document.getElementById("changelog-live-preview");
 const count = document.getElementById("changelog-char-count");
 if (!ta) return;
 const cleaned = sanitizeChangelogClient(ta.value);
 if (preview) preview.textContent = cleaned || "Preview will appear here...";
 if (count) count.textContent = `${cleaned.length} / 4000`;
}

function insertTemplate() {
 const sel = document.getElementById("changelog-template");
 const key = sel ? sel.value : "";
 const tpl = CHANGELOG_TEMPLATES[key] || CHANGELOG_TEMPLATES.patch;
 const ta = document.getElementById("changelog-input");
 if (!ta) return;
 ta.value = sanitizeChangelogClient(tpl);
 refreshChangelogPreview();
 ta.focus();
}

document.addEventListener("DOMContentLoaded", () => {
 const ta = document.getElementById("changelog-input");
 if (ta) {
 ta.addEventListener("input", refreshChangelogPreview);
 refreshChangelogPreview();
 }
});

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
