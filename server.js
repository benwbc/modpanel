// Roblox Moderation Panel API
//
// Talks to three kinds of clients:
//   1. Your Roblox game server (Adminhandler script) — POSTs violations from
//      the anti-cheat, polls for pending ban/kick/unban actions, and acks them.
//      Authenticates with the GAME_API_KEY env var via X-API-Key header.
//   2. The dashboard in /public — one login per moderator (X-Mod-Key header),
//      so access can be granted/revoked per person instead of one shared secret.
//   3. Roblox's public Users/Thumbnails APIs and (optionally) the Open Cloud
//      Data Stores API — outbound calls this server makes on the dashboard's
//      behalf so the Roblox lookup key/Open Cloud key never reach the browser.
//
// Storage is flat JSON files under ./data. That's intentional: zero setup,
// works fine on Render's free tier for a hobby project. Render's free disk
// is NOT guaranteed to persist across a redeploy — see README.md if you
// want a real database later (Supabase's free Postgres tier is the natural
// upgrade; swap the readJSON/writeJSON helpers, the rest of the API doesn't
// need to change).

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1); // Render sits behind a proxy; needed for correct req.ip
app.use(helmet({ contentSecurityPolicy: false })); // CSP off: single inline-script dashboard, no user-generated HTML is ever injected unescaped
app.use(express.json({ limit: "1mb" }));

// No CORS headers are set anywhere below, so browsers block cross-origin
// reads by default. If you deliberately want to call this API from another
// origin, set ALLOWED_ORIGIN and uncomment the block — leave it unset otherwise.
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "";
if (ALLOWED_ORIGIN) {
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Mod-Key, X-API-Key");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });
}

const PORT = process.env.PORT || 3000;
const GAME_API_KEY = process.env.GAME_API_KEY || process.env.API_KEY || ""; // API_KEY kept as a fallback name for anyone upgrading from the old single-key version
const PLACE_ID = process.env.PLACE_ID || "";
const UNIVERSE_ID = process.env.UNIVERSE_ID || "";
const GAME_NAME = process.env.GAME_NAME || "";
const OPEN_CLOUD_API_KEY = process.env.OPEN_CLOUD_API_KEY || "";
const DATASTORE_NAME = process.env.DATASTORE_NAME || "";
const DATASTORE_KEY_TEMPLATE = process.env.DATASTORE_KEY_TEMPLATE || "{userId}";

const DATA_DIR = path.join(__dirname, "data");
const VIOLATIONS_FILE = path.join(DATA_DIR, "violations.json");
const ACTIONS_FILE = path.join(DATA_DIR, "actions.json");
const MODERATORS_FILE = path.join(DATA_DIR, "moderators.json");

const MAX_VIOLATIONS_STORED = 5000;
const ACTION_RESEND_AFTER_MS = 60 * 1000; // if a "sent" action isn't acked in 60s, resend it

// ---------------------------------------------------------------
// tiny JSON-file storage helpers
// ---------------------------------------------------------------
function ensureDataFiles() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(VIOLATIONS_FILE)) fs.writeFileSync(VIOLATIONS_FILE, "[]");
  if (!fs.existsSync(ACTIONS_FILE)) fs.writeFileSync(ACTIONS_FILE, "[]");
  if (!fs.existsSync(MODERATORS_FILE)) fs.writeFileSync(MODERATORS_FILE, "[]");
}
function readJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return [];
  }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
ensureDataFiles();

// ---------------------------------------------------------------
// auth helpers
// ---------------------------------------------------------------
function hashKey(key) {
  return crypto.createHash("sha256").update(String(key)).digest("hex");
}
function safeEqualHex(a, b) {
  const bufA = Buffer.from(String(a), "utf8");
  const bufB = Buffer.from(String(b), "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// in-memory brute-force lockout, per IP, on top of the rate limiter below
const failedAttempts = new Map(); // ip -> { count, lockedUntil }
const LOCKOUT_THRESHOLD = 8;
const LOCKOUT_WINDOW_MS = 5 * 60 * 1000;
function isLockedOut(ip) {
  const rec = failedAttempts.get(ip);
  return !!(rec && rec.lockedUntil && rec.lockedUntil > Date.now());
}
function registerFailure(ip) {
  const rec = failedAttempts.get(ip) || { count: 0, lockedUntil: 0 };
  rec.count += 1;
  if (rec.count >= LOCKOUT_THRESHOLD) {
    rec.lockedUntil = Date.now() + LOCKOUT_WINDOW_MS;
    rec.count = 0;
  }
  failedAttempts.set(ip, rec);
}
function registerSuccess(ip) {
  failedAttempts.delete(ip);
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of failedAttempts) {
    if (!rec.lockedUntil || rec.lockedUntil < now) failedAttempts.delete(ip);
  }
}, 10 * 60 * 1000).unref();

// game server auth — only for the three /api routes the Adminhandler script calls
function requireGameKey(req, res, next) {
  if (!GAME_API_KEY) {
    return res.status(500).json({ error: "Server misconfigured: GAME_API_KEY is not set." });
  }
  if (isLockedOut(req.ip)) {
    return res.status(429).json({ error: "Too many failed attempts from this address. Try again later." });
  }
  const key = req.header("X-API-Key");
  if (!key || !safeEqualHex(hashKey(key), hashKey(GAME_API_KEY))) {
    registerFailure(req.ip);
    return res.status(401).json({ error: "Invalid or missing X-API-Key header." });
  }
  registerSuccess(req.ip);
  next();
}

// dashboard auth — every moderator has their own key, so access can be
// revoked individually and every action is attributed to a person.
function requireMod(minRole) {
  return (req, res, next) => {
    if (isLockedOut(req.ip)) {
      return res.status(429).json({ error: "Too many failed attempts from this address. Try again later." });
    }
    const key = req.header("X-Mod-Key");
    if (!key) {
      return res.status(401).json({ error: "Missing X-Mod-Key header." });
    }
    const mods = readJSON(MODERATORS_FILE);
    const keyHash = hashKey(key);
    const mod = mods.find((m) => safeEqualHex(m.keyHash, keyHash));
    if (!mod) {
      registerFailure(req.ip);
      return res.status(401).json({ error: "Invalid moderator key." });
    }
    registerSuccess(req.ip);
    if (minRole === "admin" && mod.role !== "admin") {
      return res.status(403).json({ error: "This action requires the admin role." });
    }
    req.moderator = { id: mod.id, username: mod.username, role: mod.role };
    next();
  };
}

function ensureBootstrapAdmin() {
  const mods = readJSON(MODERATORS_FILE);
  if (mods.length > 0) return;
  const username = process.env.ADMIN_USERNAME || "admin";
  const key = process.env.ADMIN_KEY || crypto.randomBytes(24).toString("hex");
  mods.push({
    id: crypto.randomUUID(),
    username,
    role: "admin",
    keyHash: hashKey(key),
    createdAt: Date.now(),
  });
  writeJSON(MODERATORS_FILE, mods);
  console.log("=".repeat(72));
  console.log("No moderators exist yet — created a bootstrap admin account:");
  console.log("  Username: " + username);
  console.log("  Key:      " + key);
  if (!process.env.ADMIN_KEY) {
    console.log("  (This key was randomly generated because ADMIN_KEY isn't set.");
    console.log("   It's stored only as a hash — copy it now, it won't be shown again.");
    console.log("   Set ADMIN_KEY in your environment to control it instead.)");
  }
  console.log("Log in with these on the dashboard, then add your team from Settings → Moderators.");
  console.log("=".repeat(72));
}
ensureBootstrapAdmin();

// general throttle across the whole API, generous enough for normal polling
// (dashboard refreshes every ~6s, the game polls every ~10s) but a real
// ceiling against scripted abuse.
app.use(
  "/api/",
  rateLimit({
    windowMs: 5 * 60 * 1000,
    limit: 600,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.get("/api/health", (req, res) => res.json({ ok: true }));

// ---------------------------------------------------------------
// AUTH / MODERATORS
// ---------------------------------------------------------------

// Dashboard -> here, right after login, to confirm the key and get identity + config.
app.get("/api/me", requireMod("moderator"), (req, res) => {
  res.json({
    moderator: req.moderator,
    settings: {
      placeId: PLACE_ID || null,
      universeId: UNIVERSE_ID || null,
      gameName: GAME_NAME || null,
      openCloudConfigured: !!(OPEN_CLOUD_API_KEY && UNIVERSE_ID && DATASTORE_NAME),
      gameKeyConfigured: !!GAME_API_KEY,
    },
  });
});

app.get("/api/moderators", requireMod("admin"), (req, res) => {
  const mods = readJSON(MODERATORS_FILE).map(({ id, username, role, createdAt }) => ({
    id,
    username,
    role,
    createdAt,
  }));
  res.json(mods);
});

app.post("/api/moderators", requireMod("admin"), (req, res) => {
  const { username, role } = req.body || {};
  if (!username || typeof username !== "string" || !username.trim()) {
    return res.status(400).json({ error: "username is required." });
  }
  const safeRole = role === "admin" ? "admin" : "moderator";
  const mods = readJSON(MODERATORS_FILE);
  if (mods.some((m) => m.username.toLowerCase() === username.trim().toLowerCase())) {
    return res.status(409).json({ error: "A moderator with that username already exists." });
  }
  const key = crypto.randomBytes(24).toString("hex");
  const mod = {
    id: crypto.randomUUID(),
    username: username.trim(),
    role: safeRole,
    keyHash: hashKey(key),
    createdAt: Date.now(),
    createdBy: req.moderator.username,
  };
  mods.push(mod);
  writeJSON(MODERATORS_FILE, mods);
  // the raw key is only ever returned here, once — copy it to the new moderator securely
  res.status(201).json({ id: mod.id, username: mod.username, role: mod.role, createdAt: mod.createdAt, key });
});

app.delete("/api/moderators/:id", requireMod("admin"), (req, res) => {
  const mods = readJSON(MODERATORS_FILE);
  const target = mods.find((m) => m.id === req.params.id);
  if (!target) return res.status(404).json({ error: "Moderator not found." });
  const adminCount = mods.filter((m) => m.role === "admin").length;
  if (target.role === "admin" && adminCount <= 1) {
    return res.status(400).json({ error: "Can't remove the only remaining admin." });
  }
  writeJSON(MODERATORS_FILE, mods.filter((m) => m.id !== req.params.id));
  res.json({ ok: true });
});

// ---------------------------------------------------------------
// HEARTBEAT — proves the anti-cheat link is actually alive
// ---------------------------------------------------------------
const heartbeat = { lastViolationAt: null, lastActionPollAt: null };
app.get("/api/heartbeat", requireMod("moderator"), (req, res) => res.json(heartbeat));

// ---------------------------------------------------------------
// VIOLATIONS  (anti-cheat integration)
// ---------------------------------------------------------------

// Roblox -> here. Called from Adminhandler's reportViolationToPanel().
app.post("/api/violations", requireGameKey, (req, res) => {
  const { userId, username, violationType, details, severity, jobId, placeId, timestamp } = req.body || {};

  if (!userId || !violationType) {
    return res.status(400).json({ error: "userId and violationType are required." });
  }

  const violations = readJSON(VIOLATIONS_FILE);
  violations.push({
    id: crypto.randomUUID(),
    userId,
    username: username || "Unknown",
    violationType,
    details: details || "",
    severity: severity === "ban" ? "ban" : "warning",
    jobId: jobId || null,
    placeId: placeId || PLACE_ID || null,
    timestamp: timestamp || Math.floor(Date.now() / 1000),
    receivedAt: Date.now(),
  });

  while (violations.length > MAX_VIOLATIONS_STORED) violations.shift();

  writeJSON(VIOLATIONS_FILE, violations);
  heartbeat.lastViolationAt = Date.now();
  res.status(201).json({ ok: true });
});

// Dashboard -> here. Newest first, optional filters.
app.get("/api/violations", requireMod("moderator"), (req, res) => {
  let violations = readJSON(VIOLATIONS_FILE).slice().reverse();

  const { userId, severity, search, limit } = req.query;
  if (userId) violations = violations.filter((v) => String(v.userId) === String(userId));
  if (severity) violations = violations.filter((v) => v.severity === severity);
  if (search) {
    const q = String(search).toLowerCase();
    violations = violations.filter(
      (v) =>
        v.username.toLowerCase().includes(q) ||
        v.violationType.toLowerCase().includes(q) ||
        v.details.toLowerCase().includes(q)
    );
  }

  const cap = Math.min(parseInt(limit, 10) || 200, 1000);
  res.json(violations.slice(0, cap));
});

// ---------------------------------------------------------------
// ACTIONS (ban / kick / unban queue)
// ---------------------------------------------------------------

// Dashboard -> here. Queues an action for the game server to pick up.
app.post("/api/actions", requireMod("moderator"), (req, res) => {
  const { type, userId, username, reason, notes, banLength } = req.body || {};
  if (!["ban", "kick", "unban"].includes(type) || !userId) {
    return res.status(400).json({ error: "type must be ban/kick/unban, and userId is required." });
  }

  const actions = readJSON(ACTIONS_FILE);
  const action = {
    id: crypto.randomUUID(),
    type,
    userId,
    username: username || "Unknown",
    reason: reason || "",
    notes: notes || "",
    banLength: banLength || null,
    status: "pending", // pending -> sent -> done
    createdAt: Date.now(),
    sentAt: null,
    queuedBy: req.moderator.username,
  };
  actions.push(action);
  writeJSON(ACTIONS_FILE, actions);
  res.status(201).json(action);
});

// Roblox -> here, polled every ~10s. Returns pending actions and marks
// them "sent"; if never acked, they're resent after ACTION_RESEND_AFTER_MS
// in case a server crashed mid-action.
app.get("/api/actions/pending", requireGameKey, (req, res) => {
  const actions = readJSON(ACTIONS_FILE);
  const now = Date.now();

  const due = actions.filter(
    (a) => a.status === "pending" || (a.status === "sent" && now - a.sentAt > ACTION_RESEND_AFTER_MS)
  );

  due.forEach((a) => {
    a.status = "sent";
    a.sentAt = now;
  });
  writeJSON(ACTIONS_FILE, actions);
  heartbeat.lastActionPollAt = Date.now();

  res.json(due.map(({ id, type, userId, reason, notes, banLength }) => ({ id, type, userId, reason, notes, banLength })));
});

// Roblox -> here, after executing an action.
app.post("/api/actions/ack", requireGameKey, (req, res) => {
  const { actionId } = req.body || {};
  const actions = readJSON(ACTIONS_FILE);
  const action = actions.find((a) => a.id === actionId);
  if (action) {
    action.status = "done";
    action.doneAt = Date.now();
    writeJSON(ACTIONS_FILE, actions);
  }
  res.json({ ok: true });
});

// Dashboard -> here, to show recent action history.
app.get("/api/actions", requireMod("moderator"), (req, res) => {
  const { userId } = req.query;
  let actions = readJSON(ACTIONS_FILE).slice().reverse();
  if (userId) actions = actions.filter((a) => String(a.userId) === String(userId));
  res.json(actions.slice(0, 300));
});

// ---------------------------------------------------------------
// ROBLOX LOOKUPS — proxied server-side so no Roblox/Open Cloud key
// (and no extra CORS exposure) is ever sent to the browser.
// ---------------------------------------------------------------

async function robloxFetch(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    const err = new Error(`Roblox API ${res.status}: ${body.slice(0, 200)}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// Dashboard -> here. Resolves a username or userId into a Roblox profile,
// then merges in this panel's own moderation history for that player.
app.get("/api/lookup/roblox", requireMod("moderator"), async (req, res) => {
  const { username, userId } = req.query;
  if (!username && !userId) {
    return res.status(400).json({ error: "Provide a username or userId query param." });
  }

  try {
    let profile;
    if (userId) {
      profile = await robloxFetch(`https://users.roblox.com/v1/users/${encodeURIComponent(userId)}`);
    } else {
      const search = await robloxFetch("https://users.roblox.com/v1/usernames/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ usernames: [username], excludeBannedUsers: false }),
      });
      const match = search.data && search.data[0];
      if (!match) return res.status(404).json({ error: "No Roblox user found with that username." });
      profile = await robloxFetch(`https://users.roblox.com/v1/users/${match.id}`);
    }

    let avatarUrl = null;
    try {
      const thumb = await robloxFetch(
        `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${profile.id}&size=150x150&format=Png&isCircular=false`
      );
      avatarUrl = thumb.data && thumb.data[0] && thumb.data[0].imageUrl;
    } catch {
      /* thumbnail is a nice-to-have, don't fail the lookup over it */
    }

    const violations = readJSON(VIOLATIONS_FILE).filter((v) => String(v.userId) === String(profile.id));
    const actions = readJSON(ACTIONS_FILE).filter((a) => String(a.userId) === String(profile.id));

    res.json({
      roblox: {
        id: profile.id,
        name: profile.name,
        displayName: profile.displayName,
        description: profile.description || "",
        created: profile.created,
        isBanned: !!profile.isBanned,
        avatarUrl,
        profileUrl: `https://www.roblox.com/users/${profile.id}/profile`,
      },
      moderation: {
        banStrikes: violations.filter((v) => v.severity === "ban").length,
        warnings: violations.filter((v) => v.severity === "warning").length,
        recentViolations: violations.slice(-25).reverse(),
        recentActions: actions.slice(-25).reverse(),
      },
    });
  } catch (e) {
    res.status(e.status === 404 ? 404 : 502).json({ error: e.message || "Lookup failed." });
  }
});

// Dashboard -> here, optional. Only works if OPEN_CLOUD_API_KEY / UNIVERSE_ID /
// DATASTORE_NAME are set — see README. Returns whatever your game stores in
// that DataStore entry (currency, XP, private servers, etc.) as raw JSON;
// the dashboard renders it generically since the schema is yours.
app.get("/api/lookup/gamedata/:userId", requireMod("moderator"), async (req, res) => {
  if (!(OPEN_CLOUD_API_KEY && UNIVERSE_ID && DATASTORE_NAME)) {
    return res.status(501).json({
      error:
        "Open Cloud game-data lookup isn't configured. Set OPEN_CLOUD_API_KEY, UNIVERSE_ID and DATASTORE_NAME to enable it — see README.",
    });
  }
  const entryKey = DATASTORE_KEY_TEMPLATE.replace("{userId}", req.params.userId);
  const url =
    `https://apis.roblox.com/datastores/v1/universes/${UNIVERSE_ID}/standard-datastores/datastore/entries/entry` +
    `?datastoreName=${encodeURIComponent(DATASTORE_NAME)}&entryKey=${encodeURIComponent(entryKey)}`;
  try {
    const data = await robloxFetch(url, { headers: { "x-api-key": OPEN_CLOUD_API_KEY } });
    res.json({ entryKey, data });
  } catch (e) {
    res.status(e.status === 404 ? 404 : 502).json({
      error: e.status === 404 ? `No DataStore entry found for key "${entryKey}".` : e.message,
    });
  }
});

// ---------------------------------------------------------------
// static dashboard
// ---------------------------------------------------------------
app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  console.log(`Moderation panel API listening on port ${PORT}`);
  if (!GAME_API_KEY) {
    console.warn("⚠️  GAME_API_KEY is not set — the /api/violations and /api/actions/* routes the game uses will reject every request until you set it.");
  }
});
