(() => {
  const state = {
    key: localStorage.getItem("sentinel_key") || null,
    me: null,
    config: null,
  };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  function toast(msg) {
    const el = $("#toast");
    el.textContent = msg;
    el.classList.remove("hidden");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.add("hidden"), 2600);
  }

  async function api(path, options = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
    if (state.key) headers["X-Mod-Key"] = state.key;

    const res = await fetch(path, Object.assign({}, options, { headers }));
    if (res.status === 401) {
      signOut("Your session key was rejected. Sign in again.");
      throw new Error("unauthorized");
    }
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `Request failed (${res.status})`);
    return body;
  }

  function timeAgo(iso) {
    if (!iso) return "—";
    const diff = Date.now() - new Date(iso).getTime();
    const s = Math.floor(diff / 1000);
    if (s < 60) return s + "s ago";
    const m = Math.floor(s / 60);
    if (m < 60) return m + "m ago";
    const h = Math.floor(m / 60);
    if (h < 24) return h + "h ago";
    return Math.floor(h / 24) + "d ago";
  }

  // ------------------------------------------------------------
  // AUTH
  // ------------------------------------------------------------
  function signOut(message) {
    state.key = null;
    localStorage.removeItem("sentinel_key");
    $("#app").classList.add("hidden");
    $("#loginScreen").classList.remove("hidden");
    $("#loginError").textContent = message || "";
  }

  async function signIn(key) {
    state.key = key;
    try {
      const me = await api("/api/me");
      state.me = me;
      state.config = me.config;
      localStorage.setItem("sentinel_key", key);
      $("#loginScreen").classList.add("hidden");
      $("#app").classList.remove("hidden");
      applyIdentity();
      initDashboard();
    } catch (err) {
      state.key = null;
      $("#loginError").textContent = "That key wasn't recognized.";
    }
  }

  function applyIdentity() {
    $("#whoName").textContent = state.me.username;
    $("#whoRole").textContent = state.me.role;
    $("#gameNameLabel").textContent = state.config.gameName;

    if (state.me.role !== "admin") {
      $("#adminOnlyPanel").classList.add("hidden");
    } else {
      $("#adminOnlyPanel").classList.remove("hidden");
    }

    $("#cfgGameName").textContent = state.config.gameName || "—";
    $("#cfgPlaceId").textContent = state.config.placeId || "not set";
    $("#cfgUniverseId").textContent = state.config.universeId || "not set";
    $("#cfgGameData").textContent = state.config.gameDataConfigured ? "Configured" : "Not configured";

    if (state.config.placeId) {
      const launchUrl = encodeURIComponent(
        `https://assetgame.roblox.com/game/PlaceLauncher.ashx?request=RequestGame&placeId=${state.config.placeId}`
      );
      $("#openStudioLink").href = `roblox-studio://1+launchmode:edit+placelauncherurl:${launchUrl}`;
    } else {
      $("#openStudioLink").href = "#";
    }
  }

  $("#loginForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const key = $("#loginKey").value.trim();
    if (key) signIn(key);
  });

  $("#logoutBtn").addEventListener("click", () => signOut());

  // ------------------------------------------------------------
  // NAV
  // ------------------------------------------------------------
  $$(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".nav-item").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      $$(".view").forEach((v) => v.classList.add("hidden"));
      $(`#view-${btn.dataset.view}`).classList.remove("hidden");

      if (btn.dataset.view === "actions") loadActions();
      if (btn.dataset.view === "settings" && state.me.role === "admin") loadModerators();
    });
  });

  // ------------------------------------------------------------
  // HEARTBEAT
  // ------------------------------------------------------------
  async function pollHeartbeat() {
    try {
      const hb = await api("/api/heartbeat");
      const dot = $("#heartbeatDot");
      const last = hb.lastViolationAt || hb.lastPolledAt;
      if (last && Date.now() - new Date(last).getTime() < 60_000) {
        dot.className = "dot live";
      } else if (last) {
        dot.className = "dot stale";
      } else {
        dot.className = "dot";
      }
    } catch (e) {
      /* ignore — auth failure already handled globally */
    }
  }

  // ------------------------------------------------------------
  // DASHBOARD / VIOLATIONS FEED
  // ------------------------------------------------------------
  function joinServerLink(v) {
    if (!v.placeId || !v.jobId) return null;
    return `roblox://experiences/start?placeId=${v.placeId}&gameInstanceId=${v.jobId}`;
  }

  function renderViolations(list) {
    const feed = $("#violationsFeed");
    if (!list.length) {
      feed.innerHTML = `<div class="empty-state">No violations reported yet — this fills in as your anti-cheat reports flags.</div>`;
      return;
    }

    feed.innerHTML = list
      .map((v) => {
        const join = joinServerLink(v);
        return `
        <div class="feed-row sev-${v.severity}">
          <span class="feed-badge sev-${v.severity}">${v.severity}</span>
          <div class="feed-main">
            <span class="player">${escapeHtml(v.username)}</span>
            <span class="type">${escapeHtml(v.violationType)}</span>
            <div class="details">${escapeHtml(v.details || "")}</div>
          </div>
          <div class="feed-time">${timeAgo(v.receivedAt)}</div>
          <div class="feed-links">
            <button data-lookup="${v.userId}">Lookup</button>
            ${join ? `<a href="${join}">Join server</a>` : ""}
          </div>
        </div>`;
      })
      .join("");

    feed.querySelectorAll("[data-lookup]").forEach((btn) => {
      btn.addEventListener("click", () => {
        $$(".nav-item").forEach((b) => b.classList.remove("active"));
        $('.nav-item[data-view="lookup"]').classList.add("active");
        $$(".view").forEach((v) => v.classList.add("hidden"));
        $("#view-lookup").classList.remove("hidden");
        $("#lookupInput").value = btn.dataset.lookup;
        doLookup(btn.dataset.lookup);
      });
    });
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  async function loadViolations() {
    const params = new URLSearchParams();
    const search = $("#searchInput").value.trim();
    const severity = $("#severityFilter").value;
    if (search) params.set("search", search);
    if (severity) params.set("severity", severity);
    params.set("limit", "150");

    try {
      const list = await api(`/api/violations?${params.toString()}`);
      renderViolations(list);
    } catch (err) {
      toast(err.message);
    }
  }

  $("#refreshBtn").addEventListener("click", loadViolations);
  $("#searchInput").addEventListener("input", debounce(loadViolations, 300));
  $("#severityFilter").addEventListener("change", loadViolations);

  function debounce(fn, ms) {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), ms);
    };
  }

  // ------------------------------------------------------------
  // LOOKUP
  // ------------------------------------------------------------
  async function doLookup(query) {
    const isNumeric = /^\d+$/.test(query);
    const params = isNumeric ? `userId=${encodeURIComponent(query)}` : `username=${encodeURIComponent(query)}`;
    const resultEl = $("#lookupResult");
    resultEl.innerHTML = `<p class="sub">Looking up…</p>`;

    try {
      const data = await api(`/api/lookup/roblox?${params}`);
      const p = data.profile;
      $("#actionUserId").value = p.id;

      let gameDataHtml = "";
      if (state.config.gameDataConfigured) {
        try {
          const gd = await api(`/api/lookup/gamedata/${p.id}`);
          gameDataHtml = `<h2>Live game data</h2><pre>${escapeHtml(JSON.stringify(gd.data, null, 2))}</pre>`;
        } catch (e) {
          // no entry — skip silently, as documented
        }
      }

      resultEl.innerHTML = `
        <div class="profile-row">
          ${p.avatarUrl ? `<img src="${p.avatarUrl}" alt="" />` : ""}
          <div>
            <div class="profile-name">${escapeHtml(p.displayName)} <span class="sub" style="margin:0">@${escapeHtml(p.name)}</span></div>
            <div class="profile-meta">UserId ${p.id} · joined ${new Date(p.created).toLocaleDateString()} ${p.isBanned ? "· <strong style='color:var(--danger)'>banned on Roblox</strong>" : ""}</div>
          </div>
        </div>
        <h2 style="margin-top:18px">Panel history</h2>
        ${
          data.panelHistory.violations.length
            ? data.panelHistory.violations
                .slice(0, 8)
                .map((v) => `<div class="feed-row sev-${v.severity}" style="grid-template-columns:90px 1fr 140px"><span class="feed-badge sev-${v.severity}">${v.severity}</span><div class="feed-main"><span class="player">${escapeHtml(v.violationType)}</span><div class="details">${escapeHtml(v.details || "")}</div></div><div class="feed-time">${timeAgo(v.receivedAt)}</div></div>`)
                .join("")
            : `<p class="sub" style="margin:0">No violations on record for this player.</p>`
        }
        ${gameDataHtml}
      `;
    } catch (err) {
      resultEl.innerHTML = `<p class="sub" style="color:var(--danger)">${escapeHtml(err.message)}</p>`;
    }
  }

  $("#lookupForm").addEventListener("submit", (e) => {
    e.preventDefault();
    doLookup($("#lookupInput").value.trim());
  });

  $("#actionForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = {
      type: $("#actionType").value,
      userId: $("#actionUserId").value.trim(),
      reason: $("#actionReason").value.trim(),
      notes: $("#actionNotes").value.trim(),
      banLength: $("#banLength").value,
    };
    if (!body.userId) return;

    try {
      await api("/api/actions", { method: "POST", body: JSON.stringify(body) });
      $("#actionStatus").textContent = `${body.type} queued — the game server picks it up within ~10 seconds.`;
      $("#actionReason").value = "";
      $("#actionNotes").value = "";
    } catch (err) {
      $("#actionStatus").textContent = err.message;
    }
  });

  // ------------------------------------------------------------
  // ACTION HISTORY
  // ------------------------------------------------------------
  async function loadActions() {
    const userId = $("#actionsFilterUserId").value.trim();
    const params = userId ? `?userId=${encodeURIComponent(userId)}` : "";
    try {
      const list = await api(`/api/actions${params}`);
      const feed = $("#actionsFeed");
      if (!list.length) {
        feed.innerHTML = `<div class="empty-state">No actions queued yet.</div>`;
        return;
      }
      feed.innerHTML = list
        .map(
          (a) => `
        <div class="feed-row sev-${a.type === "ban" ? "ban" : "warning"}" style="grid-template-columns:90px 1fr 140px 110px">
          <span class="feed-badge sev-${a.type === "ban" ? "ban" : "warning"}">${a.type}</span>
          <div class="feed-main">
            <span class="player">UserId ${a.userId}</span>
            <span class="type">by ${escapeHtml(a.queuedBy)}</span>
            <div class="details">${escapeHtml(a.reason || "")}</div>
          </div>
          <div class="feed-time">${timeAgo(a.queuedAt)}</div>
          <div class="feed-links"><span style="color:${a.acknowledged ? "var(--success)" : "var(--text-faint)"}">${a.acknowledged ? "done" : "pending"}</span></div>
        </div>`
        )
        .join("");
    } catch (err) {
      toast(err.message);
    }
  }
  $("#actionsRefreshBtn").addEventListener("click", loadActions);
  $("#actionsFilterUserId").addEventListener("input", debounce(loadActions, 300));

  // ------------------------------------------------------------
  // MODERATORS (add users)
  // ------------------------------------------------------------
  async function loadModerators() {
    try {
      const list = await api("/api/moderators");
      $("#modTableBody").innerHTML = list
        .map(
          (m) => `
        <tr>
          <td>${escapeHtml(m.username)}</td>
          <td class="${m.role === "admin" ? "role-admin" : ""}">${m.role}</td>
          <td>${new Date(m.createdAt).toLocaleDateString()}</td>
          <td><button class="revoke-btn" data-id="${m.id}">Revoke</button></td>
        </tr>`
        )
        .join("");

      $("#modTableBody").querySelectorAll(".revoke-btn").forEach((btn) => {
        btn.addEventListener("click", async () => {
          if (!confirm("Revoke this moderator's access?")) return;
          try {
            await api(`/api/moderators/${btn.dataset.id}`, { method: "DELETE" });
            loadModerators();
          } catch (err) {
            toast(err.message);
          }
        });
      });
    } catch (err) {
      toast(err.message);
    }
  }

  $("#addModBtn").addEventListener("click", () => $("#addModModal").classList.remove("hidden"));
  $("#addModCancel").addEventListener("click", () => $("#addModModal").classList.add("hidden"));

  $("#addModForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = $("#newModUsername").value.trim();
    const role = $("#newModRole").value;
    try {
      const result = await api("/api/moderators", {
        method: "POST",
        body: JSON.stringify({ username, role }),
      });
      $("#addModModal").classList.add("hidden");
      $("#addModForm").reset();
      $("#newKeyDisplay").textContent = result.key;
      $("#newKeyModal").classList.remove("hidden");
      loadModerators();
    } catch (err) {
      toast(err.message);
    }
  });

  $("#newKeyClose").addEventListener("click", () => $("#newKeyModal").classList.add("hidden"));

  // ------------------------------------------------------------
  // INIT
  // ------------------------------------------------------------
  function initDashboard() {
    loadViolations();
    pollHeartbeat();
    setInterval(loadViolations, 15000);
    setInterval(pollHeartbeat, 15000);
  }

  if (state.key) signIn(state.key);
})();
