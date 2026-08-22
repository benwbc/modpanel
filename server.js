// Roblox Moderation Panel API
//
// Talks to two clients:
//   1. Your Roblox game server (Adminhandler script) — POSTs violations,
//      polls for pending ban/kick/unban actions, and acks them.
//   2. The dashboard in /public — reads violations, looks up users, queues actions.
//
// Storage is flat JSON files. That's intentional: it needs zero setup and
// works great on Render's free tier for a hobby project. The one caveat is
// Render's free disk is NOT guaranteed to persist across a redeploy — see
// README.md if you want a real database later (Supabase's free Postgres
// tier is the natural upgrade, no rewrite required, just swap readJSON/
// writeJSON for real queries).

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", 1); // Render sits behind a proxy; needed for req.ip to be the real client IP
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || "changeme-set-a-real-key";
const DATA_DIR = path.join(__dirname, "data");
const VIOLATIONS_FILE = path.join(DATA_DIR, "violations.json");
const ACTIONS_FILE = path.join(DATA_DIR, "actions.json");
const BANS_FILE = path.join(DATA_DIR, "bans.json");

const MAX_VIOLATIONS_STORED = 5000;
const ACTION_RESEND_AFTER_MS = 60 * 1000; // if a "sent" action isn't acked in 60s, resend it

// ---------------------------------------------------------------
// tiny JSON-file storage helpers
// ---------------------------------------------------------------
function ensureDataFiles() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(VIOLATIONS_FILE)) fs.writeFileSync(VIOLATIONS_FILE, "[]");
  if (!fs.existsSync(ACTIONS_FILE)) fs.writeFileSync(ACTIONS_FILE, "[]");
  if (!fs.existsSync(BANS_FILE)) fs.writeFileSync(BANS_FILE, "{}"); // { [userId]: { reason, bannedAt, bannedBy } }
}
function readJSON(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
ensureDataFiles();

// ---------------------------------------------------------------
// AUTH
//   - constant-time key comparison (avoids leaking timing info to an
//     attacker probing byte-by-byte)
//   - per-IP lockout after repeated bad keys, so the login box can't be
//     brute-forced from the internet
// ---------------------------------------------------------------
const failedAttempts = new Map(); // ip -> { count, firstAttemptAt, lockedUntil }
const MAX_ATTEMPTS = 8;
const LOCKOUT_MS = 10 * 60 * 1000; // 10 minutes
const ATTEMPT_WINDOW_MS = 5 * 60 * 1000;

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) {
    // still run a same-shape comparison so mismatched lengths don't return faster
    crypto.timingSafeEqual(bufA, Buffer.concat([bufB, Buffer.alloc(Math.max(0, bufA.length - bufB.length))]).subarray(0, bufA.length) === bufA ? bufA : bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function requireApiKey(req, res, next) {
  const ip = req.ip || "unknown";
  const record = failedAttempts.get(ip);

  if (record && record.lockedUntil && Date.now() < record.lockedUntil) {
    const secondsLeft = Math.ceil((record.lockedUntil - Date.now()) / 1000);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${secondsLeft}s.` });
  }

  const key = req.header("X-API-Key");
  if (!key || !safeEqual(key, API_KEY)) {
    const now = Date.now();
    const attempt = record && now - record.firstAttemptAt < ATTEMPT_WINDOW_MS ? record : { count: 0, firstAttemptAt: now };
    attempt.count += 1;
    if (attempt.count >= MAX_ATTEMPTS) {
      attempt.lockedUntil = now + LOCKOUT_MS;
      console.warn(`[security] IP ${ip} locked out after ${attempt.count} failed API key attempts.`);
    }
    failedAttempts.set(ip, attempt);
    return res.status(401).json({ error: "Invalid or missing X-API-Key header." });
  }

  failedAttempts.delete(ip); // reset on success
  next();
}

app.get("/api/health", (req, res) => res.json({ ok: true }));

// ---------------------------------------------------------------
// VIOLATIONS
// ---------------------------------------------------------------

// Roblox -> here. Called from Adminhandler's reportViolationToPanel().
app.post("/api/violations", requireApiKey, (req, res) => {
  const { userId, username, violationType, details, severity, jobId, placeId, timestamp } = req.body || {};

  if (!userId || !violationType) {
    return res.status(400).json({ error: "userId and violationType are required." });
  }

  const violations = readJSON(VIOLATIONS_FILE, []);
  violations.push({
    id: crypto.randomUUID(),
    userId,
    username: username || "Unknown",
    violationType,
    details: details || "",
    severity: severity === "ban" ? "ban" : "warning",
    jobId: jobId || null,
    placeId: placeId || null,
    timestamp: timestamp || Math.floor(Date.now() / 1000),
    receivedAt: Date.now(),
  });

  while (violations.length > MAX_VIOLATIONS_STORED) violations.shift();

  writeJSON(VIOLATIONS_FILE, violations);
  res.status(201).json({ ok: true });
});

// Dashboard -> here. Newest first, optional filters.
app.get("/api/violations", requireApiKey, (req, res) => {
  let violations = readJSON(VIOLATIONS_FILE, []).slice().reverse();

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
// LOOKUP — everything the panel knows about one player, in one call.
// (Currency / XP / playtime / purchase history from the game's own
// DataStores are NOT included here — the game doesn't currently report
// them to this panel. See README "Extending lookup" if you want that.)
// ---------------------------------------------------------------
app.get("/api/lookup", requireApiKey, (req, res) => {
  const { username, userId } = req.query;
  if (!username && !userId) {
    return res.status(400).json({ error: "Provide ?username= or ?userId=" });
  }

  const violations = readJSON(VIOLATIONS_FILE, []);
  let matches;
  if (userId) {
    matches = violations.filter((v) => String(v.userId) === String(userId));
  } else {
    const q = String(username).toLowerCase();
    matches = violations.filter((v) => v.username.toLowerCase() === q);
  }

  if (matches.length === 0 && !userId) {
    return res.status(404).json({ error: "No record of that username. They may not have triggered any checks yet." });
  }

  const resolvedUserId = userId ? String(userId) : String(matches[0].userId);
  const resolvedUsername = matches.length ? matches[matches.length - 1].username : username;

  const bans = readJSON(BANS_FILE, {});
  const banRecord = bans[resolvedUserId] || null;

  const actions = readJSON(ACTIONS_FILE, [])
    .filter((a) => String(a.userId) === resolvedUserId)
    .sort((a, b) => b.createdAt - a.createdAt);

  const sorted = matches.slice().sort((a, b) => b.timestamp - a.timestamp);

  res.json({
    userId: resolvedUserId,
    username: resolvedUsername,
    banned: !!banRecord,
    banReason: banRecord ? banRecord.reason : null,
    bannedAt: banRecord ? banRecord.bannedAt : null,
    bannedBy: banRecord ? banRecord.bannedBy : null,
    totalViolations: matches.length,
    totalBanFlags: matches.filter((v) => v.severity === "ban").length,
    totalWarnings: matches.filter((v) => v.severity === "warning").length,
    violations: sorted,
    actionHistory: actions,
  });
});

// ---------------------------------------------------------------
// ACTIONS (ban / kick / unban queue)
// ---------------------------------------------------------------

// Dashboard -> here. Queues an action for the game server to pick up.
app.post("/api/actions", requireApiKey, (req, res) => {
  const { type, userId, username, reason, issuedBy } = req.body || {};
  if (!["ban", "kick", "unban"].includes(type) || !userId) {
    return res.status(400).json({ error: "type must be ban/kick/unban, and userId is required." });
  }

  const actions = readJSON(ACTIONS_FILE, []);
  const action = {
    id: crypto.randomUUID(),
    type,
    userId,
    username: username || "Unknown",
    reason: reason || "",
    issuedBy: issuedBy || "Unknown staff",
    status: "pending", // pending -> sent -> done
    createdAt: Date.now(),
    sentAt: null,
  };
  actions.push(action);
  writeJSON(ACTIONS_FILE, actions);
  res.status(201).json(action);
});

// Roblox -> here, polled every ~10s. Returns pending actions and marks
// them "sent"; if never acked, they're resent after ACTION_RESEND_AFTER_MS
// in case a server crashed mid-action.
app.get("/api/actions/pending", requireApiKey, (req, res) => {
  const actions = readJSON(ACTIONS_FILE, []);
  const now = Date.now();

  const due = actions.filter(
    (a) => a.status === "pending" || (a.status === "sent" && now - a.sentAt > ACTION_RESEND_AFTER_MS)
  );

  due.forEach((a) => {
    a.status = "sent";
    a.sentAt = now;
  });
  writeJSON(ACTIONS_FILE, actions);

  res.json(due.map(({ id, type, userId, reason }) => ({ id, type, userId, reason })));
});

// Roblox -> here, after executing an action. Also keeps the panel's own
// ban list in sync so /api/lookup can show live ban status.
app.post("/api/actions/ack", requireApiKey, (req, res) => {
  const { actionId } = req.body || {};
  const actions = readJSON(ACTIONS_FILE, []);
  const action = actions.find((a) => a.id === actionId);

  if (action) {
    action.status = "done";
    action.doneAt = Date.now();
    writeJSON(ACTIONS_FILE, actions);

    const bans = readJSON(BANS_FILE, {});
    const key = String(action.userId);
    if (action.type === "ban") {
      bans[key] = { reason: action.reason, bannedAt: Date.now(), bannedBy: action.issuedBy || "Unknown staff" };
      writeJSON(BANS_FILE, bans);
    } else if (action.type === "unban") {
      delete bans[key];
      writeJSON(BANS_FILE, bans);
    }
  }

  res.json({ ok: true });
});

// Dashboard -> here, to show recent action history.
app.get("/api/actions", requireApiKey, (req, res) => {
  const actions = readJSON(ACTIONS_FILE, []).slice().reverse();
  res.json(actions.slice(0, 200));
});

// Dashboard -> here, list of everyone currently banned per the panel's records.
app.get("/api/bans", requireApiKey, (req, res) => {
  const bans = readJSON(BANS_FILE, {});
  res.json(Object.entries(bans).map(([userId, info]) => ({ userId, ...info })));
});

// ---------------------------------------------------------------
// static dashboard
// ---------------------------------------------------------------
app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  console.log(`Moderation panel API listening on port ${PORT}`);
  if (API_KEY === "changeme-set-a-real-key") {
    console.warn("⚠️  API_KEY is still the default — set a real one via the API_KEY environment variable!");
  }
});
