// Sentinel — Roblox Moderation Panel
// Full implementation matching README.md's API reference.

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const https = require("https");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, "data");
const VIOLATIONS_FILE = path.join(DATA_DIR, "violations.json");
const ACTIONS_FILE = path.join(DATA_DIR, "actions.json");
const MODERATORS_FILE = path.join(DATA_DIR, "moderators.json"); // fallback only, used if DATABASE_URL isn't set
const HEARTBEAT_FILE = path.join(DATA_DIR, "heartbeat.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ---- Postgres (Supabase/Neon) — persists moderator accounts across
// redeploys, since Render's free disk is NOT guaranteed to survive one.
// Everything else (violations/actions/heartbeat) still lives on local disk;
// losing that history on a redeploy is a lot less painful than every
// moderator's key resetting.
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    })
  : null;

async function ensureModeratorsTable() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS moderators (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS datastore_configs (
      id TEXT PRIMARY KEY,
      label TEXT NOT NULL,
      datastore_name TEXT NOT NULL,
      key_template TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL
    )
  `);
}

function rowToDatastoreConfig(row) {
  return {
    id: row.id,
    label: row.label,
    datastoreName: row.datastore_name,
    keyTemplate: row.key_template,
    createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
  };
}

function rowToModerator(row) {
  return {
    id: row.id,
    username: row.username,
    keyHash: row.key_hash,
    role: row.role,
    createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
  };
}

function readJSON(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const raw = fs.readFileSync(file, "utf8");
    if (!raw.trim()) return fallback;
    return JSON.parse(raw);
  } catch (err) {
    console.error(`[Sentinel] Failed to read ${file}:`, err.message);
    return fallback;
  }
}

function writeJSON(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(`[Sentinel] Failed to write ${file}:`, err.message);
  }
}

// ============================================================
// CONFIG
// ============================================================
const GAME_API_KEY = process.env.GAME_API_KEY;
const PLACE_ID = process.env.PLACE_ID || "";
const UNIVERSE_ID = process.env.UNIVERSE_ID || "";
const GAME_NAME = process.env.GAME_NAME || "Roblox Game";
const OPEN_CLOUD_API_KEY = process.env.OPEN_CLOUD_API_KEY || "";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "";

if (!GAME_API_KEY) {
  console.error("[Sentinel] FATAL: GAME_API_KEY environment variable is required.");
  console.error("[Sentinel] Generate one with: openssl rand -hex 24");
  process.exit(1);
}

// ============================================================
// SECURITY MIDDLEWARE
// ============================================================
app.use(helmet());
app.use(express.json({ limit: "256kb" }));

if (ALLOWED_ORIGIN) {
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-API-Key, X-Mod-Key");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });
}

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(express.static(path.join(__dirname, "public")));

// ---- hashing / timing-safe comparison helpers ----
function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function timingSafeEqualHex(hexA, hexB) {
  if (typeof hexA !== "string" || typeof hexB !== "string") return false;
  const a = Buffer.from(hexA, "hex");
  const b = Buffer.from(hexB, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function generateKey() {
  return crypto.randomBytes(24).toString("hex");
}

// ---- per-IP lockout on repeated bad keys ----
const failedAttempts = new Map(); // ip -> { count, lockedUntil }
const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_MS = 5 * 60 * 1000;

function isLockedOut(ip) {
  const entry = failedAttempts.get(ip);
  if (!entry) return false;
  if (entry.lockedUntil && entry.lockedUntil > Date.now()) return true;
  if (entry.lockedUntil && entry.lockedUntil <= Date.now()) failedAttempts.delete(ip);
  return false;
}

function recordFailure(ip) {
  const entry = failedAttempts.get(ip) || { count: 0, lockedUntil: 0 };
  entry.count += 1;
  if (entry.count >= LOCKOUT_THRESHOLD) {
    entry.lockedUntil = Date.now() + LOCKOUT_MS;
    entry.count = 0;
  }
  failedAttempts.set(ip, entry);
}

function recordSuccess(ip) {
  failedAttempts.delete(ip);
}

// ============================================================
// MODERATOR STORE
// ============================================================
// In-memory cache of moderators — kept in sync with whichever backing store
// is active (Postgres if DATABASE_URL is set, otherwise the local JSON
// file), so the rest of the codebase (findModeratorByKey, etc.) can keep
// reading it synchronously without every route becoming async-heavy.
let moderators = [];

async function loadModerators() {
  if (pool) {
    const { rows } = await pool.query("SELECT * FROM moderators ORDER BY created_at ASC");
    moderators = rows.map(rowToModerator);
  } else {
    moderators = readJSON(MODERATORS_FILE, []);
  }
}

async function insertModerator(entry) {
  moderators.push(entry);
  if (pool) {
    await pool.query(
      "INSERT INTO moderators (id, username, key_hash, role, created_at) VALUES ($1, $2, $3, $4, $5)",
      [entry.id, entry.username, entry.keyHash, entry.role, entry.createdAt]
    );
  } else {
    writeJSON(MODERATORS_FILE, moderators);
  }
}

async function updateModerator(entry) {
  const idx = moderators.findIndex((m) => m.id === entry.id);
  if (idx !== -1) moderators[idx] = entry;
  if (pool) {
    await pool.query(
      "UPDATE moderators SET username = $2, key_hash = $3, role = $4 WHERE id = $1",
      [entry.id, entry.username, entry.keyHash, entry.role]
    );
  } else {
    writeJSON(MODERATORS_FILE, moderators);
  }
}

async function deleteModerator(id) {
  moderators = moderators.filter((m) => m.id !== id);
  if (pool) {
    await pool.query("DELETE FROM moderators WHERE id = $1", [id]);
  } else {
    writeJSON(MODERATORS_FILE, moderators);
  }
}

// ---- DataStore configs — lets staff wire up MULTIPLE named DataStores
// (e.g. "Stats", "Currency", "Inventory") instead of just one. A player
// lookup queries all of them in parallel and shows whatever comes back.
const DATASTORE_CONFIGS_FILE = path.join(DATA_DIR, "datastore-configs.json"); // fallback only

let datastoreConfigs = [];

async function loadDatastoreConfigs() {
  if (pool) {
    const { rows } = await pool.query("SELECT * FROM datastore_configs ORDER BY created_at ASC");
    datastoreConfigs = rows.map(rowToDatastoreConfig);
  } else {
    datastoreConfigs = readJSON(DATASTORE_CONFIGS_FILE, []);
  }
}

async function insertDatastoreConfig(entry) {
  datastoreConfigs.push(entry);
  if (pool) {
    await pool.query(
      "INSERT INTO datastore_configs (id, label, datastore_name, key_template, created_at) VALUES ($1, $2, $3, $4, $5)",
      [entry.id, entry.label, entry.datastoreName, entry.keyTemplate, entry.createdAt]
    );
  } else {
    writeJSON(DATASTORE_CONFIGS_FILE, datastoreConfigs);
  }
}

async function deleteDatastoreConfig(id) {
  datastoreConfigs = datastoreConfigs.filter((d) => d.id !== id);
  if (pool) {
    await pool.query("DELETE FROM datastore_configs WHERE id = $1", [id]);
  } else {
    writeJSON(DATASTORE_CONFIGS_FILE, datastoreConfigs);
  }
}

async function bootstrapAdminIfNeeded() {
  await ensureModeratorsTable();
  await loadModerators();
  await loadDatastoreConfigs();

  if (moderators.length > 0) return;

  const username = process.env.ADMIN_USERNAME || "admin";
  const key = process.env.ADMIN_KEY || generateKey();

  await insertModerator({
    id: crypto.randomUUID(),
    username,
    keyHash: sha256(key),
    role: "admin",
    createdAt: new Date().toISOString(),
  });

  console.log("============================================================");
  console.log("[Sentinel] Bootstrap admin account created:");
  console.log(`  Username: ${username}`);
  console.log(`  Key:      ${key}`);
  console.log("  This key is shown ONCE — store it in a password manager.");
  console.log(pool ? "  Stored in Postgres — safe across redeploys." : "  Stored in local JSON — WILL reset on a redeploy that wipes disk.");
  console.log("============================================================");
}

function findModeratorByKey(key) {
  if (!key) return null;
  const hash = sha256(key);
  return moderators.find((m) => timingSafeEqualHex(m.keyHash, hash)) || null;
}

// ---- game auth (X-API-Key) ----
function requireGameAuth(req, res, next) {
  const ip = req.ip;
  if (isLockedOut(ip)) return res.status(429).json({ error: "Too many failed attempts. Try again later." });

  const key = req.header("X-API-Key");
  if (!key || key !== GAME_API_KEY) {
    recordFailure(ip);
    return res.status(401).json({ error: "Invalid or missing X-API-Key." });
  }
  recordSuccess(ip);
  next();
}

// ---- moderator auth (X-Mod-Key) ----
function requireModAuth(req, res, next) {
  const ip = req.ip;
  if (isLockedOut(ip)) return res.status(429).json({ error: "Too many failed attempts. Try again later." });

  const key = req.header("X-Mod-Key");
  const mod = findModeratorByKey(key);
  if (!mod) {
    recordFailure(ip);
    return res.status(401).json({ error: "Invalid or missing X-Mod-Key." });
  }
  recordSuccess(ip);
  req.moderator = mod;
  next();
}

function requireAdmin(req, res, next) {
  if (req.moderator.role !== "admin") {
    return res.status(403).json({ error: "Admin role required." });
  }
  next();
}

// ============================================================
// VIOLATIONS
// ============================================================
let violations = readJSON(VIOLATIONS_FILE, []);
const MAX_VIOLATIONS_STORED = 5000;

function saveViolations() {
  writeJSON(VIOLATIONS_FILE, violations);
}

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

app.post("/api/violations", requireGameAuth, (req, res) => {
  const { userId, username, violationType, details, severity, jobId, placeId, timestamp } = req.body || {};
  if (!userId || !violationType) {
    return res.status(400).json({ error: "userId and violationType are required." });
  }

  const entry = {
    id: crypto.randomUUID(),
    userId,
    username: username || String(userId),
    violationType,
    details: details || "",
    severity: severity === "ban" ? "ban" : "warning",
    jobId: jobId || null,
    placeId: placeId || PLACE_ID || null,
    timestamp: timestamp || Math.floor(Date.now() / 1000),
    receivedAt: new Date().toISOString(),
  };

  violations.unshift(entry);
  if (violations.length > MAX_VIOLATIONS_STORED) violations.length = MAX_VIOLATIONS_STORED;
  saveViolations();

  writeJSON(HEARTBEAT_FILE, { lastViolationAt: new Date().toISOString() });

  res.json({ ok: true, id: entry.id });
});

app.get("/api/violations", requireModAuth, (req, res) => {
  const { userId, severity, search, limit } = req.query;
  let results = violations;

  if (userId) results = results.filter((v) => String(v.userId) === String(userId));
  if (severity) results = results.filter((v) => v.severity === severity);
  if (search) {
    const q = String(search).toLowerCase();
    results = results.filter(
      (v) =>
        v.username.toLowerCase().includes(q) ||
        v.violationType.toLowerCase().includes(q) ||
        (v.details || "").toLowerCase().includes(q)
    );
  }

  const cap = Math.min(parseInt(limit, 10) || 100, 1000);
  res.json(results.slice(0, cap));
});

// ============================================================
// ACTIONS (ban / kick / unban queue)
// ============================================================
let actions = readJSON(ACTIONS_FILE, []);
const MAX_ACTIONS_STORED = 5000;

function saveActions() {
  writeJSON(ACTIONS_FILE, actions);
}

app.post("/api/actions", requireModAuth, (req, res) => {
  const { type, userId, reason, notes, banLength } = req.body || {};
  if (!["ban", "kick", "unban"].includes(type) || !userId) {
    return res.status(400).json({ error: "type (ban|kick|unban) and userId are required." });
  }

  const entry = {
    id: crypto.randomUUID(),
    type,
    userId,
    reason: reason || "",
    notes: notes || "",
    banLength: banLength || null,
    queuedBy: req.moderator.username,
    queuedAt: new Date().toISOString(),
    acknowledged: false,
  };

  actions.unshift(entry);
  if (actions.length > MAX_ACTIONS_STORED) actions.length = MAX_ACTIONS_STORED;
  saveActions();

  res.json({ ok: true, id: entry.id });
});

app.get("/api/actions/pending", requireGameAuth, (req, res) => {
  const pending = actions.filter((a) => !a.acknowledged);
  writeJSON(HEARTBEAT_FILE, {
    ...readJSON(HEARTBEAT_FILE, {}),
    lastPolledAt: new Date().toISOString(),
  });
  res.json(pending);
});

app.post("/api/actions/ack", requireGameAuth, (req, res) => {
  const { actionId } = req.body || {};
  const entry = actions.find((a) => a.id === actionId);
  if (entry) {
    entry.acknowledged = true;
    entry.acknowledgedAt = new Date().toISOString();
    saveActions();
  }
  res.json({ ok: true });
});

app.get("/api/actions", requireModAuth, (req, res) => {
  const { userId } = req.query;
  let results = actions;
  if (userId) results = results.filter((a) => String(a.userId) === String(userId));
  res.json(results.slice(0, 200));
});

// ============================================================
// HEARTBEAT
// ============================================================
app.get("/api/heartbeat", requireModAuth, (req, res) => {
  res.json(readJSON(HEARTBEAT_FILE, { lastViolationAt: null, lastPolledAt: null }));
});

// ============================================================
// ME / CONFIG
// ============================================================
app.get("/api/me", requireModAuth, (req, res) => {
  res.json({
    username: req.moderator.username,
    role: req.moderator.role,
    id: req.moderator.id,
    config: {
      gameName: GAME_NAME,
      placeId: PLACE_ID,
      universeId: UNIVERSE_ID,
      gameDataConfigured: Boolean(OPEN_CLOUD_API_KEY && UNIVERSE_ID && datastoreConfigs.length > 0),
    },
  });
});

// ============================================================
// DATASTORE CONFIGS (admin only) — wire up multiple named DataStores
// ============================================================
app.get("/api/datastores", requireModAuth, requireAdmin, (req, res) => {
  res.json(datastoreConfigs);
});

app.post("/api/datastores", requireModAuth, requireAdmin, async (req, res) => {
  const { label, datastoreName, keyTemplate } = req.body || {};
  if (!label || typeof label !== "string" || !label.trim()) {
    return res.status(400).json({ error: "label is required." });
  }
  if (!datastoreName || typeof datastoreName !== "string" || !datastoreName.trim()) {
    return res.status(400).json({ error: "datastoreName is required." });
  }
  const template = (typeof keyTemplate === "string" && keyTemplate.trim()) || "{userId}";
  if (!template.includes("{userId}")) {
    return res.status(400).json({ error: "keyTemplate must include {userId}." });
  }

  const entry = {
    id: crypto.randomUUID(),
    label: label.trim(),
    datastoreName: datastoreName.trim(),
    keyTemplate: template,
    createdAt: new Date().toISOString(),
  };

  try {
    await insertDatastoreConfig(entry);
  } catch (err) {
    console.error("[Sentinel] Failed to save DataStore config:", err.message);
    return res.status(500).json({ error: "Failed to save DataStore config." });
  }

  res.json(entry);
});

app.delete("/api/datastores/:id", requireModAuth, requireAdmin, async (req, res) => {
  const target = datastoreConfigs.find((d) => d.id === req.params.id);
  if (!target) return res.status(404).json({ error: "DataStore config not found." });

  try {
    await deleteDatastoreConfig(req.params.id);
  } catch (err) {
    console.error("[Sentinel] Failed to delete DataStore config:", err.message);
    return res.status(500).json({ error: "Failed to delete DataStore config." });
  }

  res.json({ ok: true });
});

// ============================================================
// MODERATORS (admin only) — "add users" management
// ============================================================
app.get("/api/moderators", requireModAuth, requireAdmin, (req, res) => {
  res.json(
    moderators.map((m) => ({
      id: m.id,
      username: m.username,
      role: m.role,
      createdAt: m.createdAt,
    }))
  );
});

app.post("/api/moderators", requireModAuth, requireAdmin, async (req, res) => {
  const { username, role } = req.body || {};
  if (!username || typeof username !== "string") {
    return res.status(400).json({ error: "username is required." });
  }
  const normalizedRole = role === "admin" ? "admin" : "moderator";
  if (moderators.some((m) => m.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: "That username is already in use." });
  }

  const key = generateKey();
  const entry = {
    id: crypto.randomUUID(),
    username,
    keyHash: sha256(key),
    role: normalizedRole,
    createdAt: new Date().toISOString(),
  };

  try {
    await insertModerator(entry);
  } catch (err) {
    console.error("[Sentinel] Failed to save moderator:", err.message);
    return res.status(500).json({ error: "Failed to save moderator." });
  }

  res.json({ id: entry.id, username: entry.username, role: entry.role, key });
});

app.put("/api/moderators/:id", requireModAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const target = moderators.find((m) => m.id === id);
  if (!target) return res.status(404).json({ error: "Moderator not found." });

  const { username, role } = req.body || {};

  if (username && typeof username === "string" && username.trim()) {
    const trimmed = username.trim();
    const clash = moderators.some(
      (m) => m.id !== id && m.username.toLowerCase() === trimmed.toLowerCase()
    );
    if (clash) return res.status(409).json({ error: "That username is already in use." });
    target.username = trimmed;
  }

  if (role && ["admin", "moderator"].includes(role)) {
    const wasAdmin = target.role === "admin";
    const admins = moderators.filter((m) => m.role === "admin");
    if (wasAdmin && role !== "admin" && admins.length <= 1) {
      return res.status(400).json({ error: "Can't demote the last remaining admin." });
    }
    target.role = role;
  }

  try {
    await updateModerator(target);
  } catch (err) {
    console.error("[Sentinel] Failed to update moderator:", err.message);
    return res.status(500).json({ error: "Failed to update moderator." });
  }

  res.json({ id: target.id, username: target.username, role: target.role, createdAt: target.createdAt });
});

app.delete("/api/moderators/:id", requireModAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const target = moderators.find((m) => m.id === id);
  if (!target) return res.status(404).json({ error: "Moderator not found." });

  const admins = moderators.filter((m) => m.role === "admin");
  if (target.role === "admin" && admins.length <= 1) {
    return res.status(400).json({ error: "Can't delete the last remaining admin account." });
  }

  try {
    await deleteModerator(id);
  } catch (err) {
    console.error("[Sentinel] Failed to delete moderator:", err.message);
    return res.status(500).json({ error: "Failed to delete moderator." });
  }

  res.json({ ok: true });
});

// ============================================================
// ROBLOX LOOKUP
// ============================================================
function httpsJSON(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null });
        } catch (e) {
          resolve({ status: res.statusCode, body: null });
        }
      });
    });
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

app.get("/api/lookup/roblox", requireModAuth, async (req, res) => {
  try {
    let { username, userId } = req.query;

    if (!userId && username) {
      const result = await httpsJSON(
        {
          hostname: "users.roblox.com",
          path: "/v1/usernames/users",
          method: "POST",
          headers: { "Content-Type": "application/json" },
        },
        { usernames: [username], excludeBannedUsers: false }
      );
      const match = result.body && result.body.data && result.body.data[0];
      if (!match) return res.status(404).json({ error: "No Roblox user found with that username." });
      userId = match.id;
    }

    if (!userId) return res.status(400).json({ error: "Provide ?username= or ?userId=" });

    const profile = await httpsJSON({
      hostname: "users.roblox.com",
      path: `/v1/users/${encodeURIComponent(userId)}`,
      method: "GET",
    });

    if (profile.status !== 200 || !profile.body) {
      return res.status(404).json({ error: "Roblox user not found." });
    }

    const thumb = await httpsJSON({
      hostname: "thumbnails.roblox.com",
      path: `/v1/users/avatar-headshot?userIds=${encodeURIComponent(userId)}&size=150x150&format=Png&isCircular=false`,
      method: "GET",
    });
    const avatarUrl =
      (thumb.body && thumb.body.data && thumb.body.data[0] && thumb.body.data[0].imageUrl) || null;

    const history = violations.filter((v) => String(v.userId) === String(userId)).slice(0, 25);
    const banHistory = actions.filter(
      (a) => String(a.userId) === String(userId) && ["ban", "kick", "unban"].includes(a.type)
    );

    res.json({
      profile: {
        id: profile.body.id,
        name: profile.body.name,
        displayName: profile.body.displayName,
        description: profile.body.description,
        created: profile.body.created,
        isBanned: profile.body.isBanned,
        avatarUrl,
      },
      panelHistory: {
        violations: history,
        actions: banHistory,
      },
    });
  } catch (err) {
    console.error("[Sentinel] Lookup failed:", err.message);
    res.status(502).json({ error: "Lookup failed — Roblox APIs may be unreachable." });
  }
});

app.get("/api/lookup/gamedata/:id", requireModAuth, async (req, res) => {
  if (!OPEN_CLOUD_API_KEY || !UNIVERSE_ID || datastoreConfigs.length === 0) {
    return res.status(404).json({ error: "Live game data isn't configured on this panel." });
  }

  const results = await Promise.all(
    datastoreConfigs.map(async (cfg) => {
      try {
        const entryKey = cfg.keyTemplate.replace("{userId}", req.params.id);
        const result = await httpsJSON({
          hostname: "apis.roblox.com",
          path: `/datastores/v1/universes/${UNIVERSE_ID}/standard-datastores/datastore/entries/entry?datastoreName=${encodeURIComponent(
            cfg.datastoreName
          )}&entryKey=${encodeURIComponent(entryKey)}`,
          method: "GET",
          headers: { "x-api-key": OPEN_CLOUD_API_KEY },
        });

        if (result.status !== 200) {
          return { id: cfg.id, label: cfg.label, datastoreName: cfg.datastoreName, found: false };
        }
        return { id: cfg.id, label: cfg.label, datastoreName: cfg.datastoreName, found: true, data: result.body };
      } catch (err) {
        return {
          id: cfg.id,
          label: cfg.label,
          datastoreName: cfg.datastoreName,
          found: false,
          error: "Request failed",
        };
      }
    })
  );

  const anyFound = results.some((r) => r.found);
  res.json({ datastores: results, anyFound });
});

// ============================================================
// FALLBACK — serve the dashboard for any non-API GET
// ============================================================
app.get(/^(?!\/api\/).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

bootstrapAdminIfNeeded()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`[Sentinel] Listening on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("[Sentinel] Failed to start:", err);
    process.exit(1);
  });
