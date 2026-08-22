// Roblox Moderation Panel API
//
// Talks to two clients:
//   1. Your Roblox game server (Adminhandler script) — POSTs violations,
//      polls for pending ban/kick/unban actions, and acks them.
//   2. The dashboard in /public — reads violations, queues actions.
//
// Storage is two flat JSON files. That's intentional: it needs zero setup
// and works great on Render's free tier for a hobby project. The one
// caveat is Render's free disk is NOT guaranteed to persist across a
// redeploy — see README.md if you want a real database later (Supabase's
// free Postgres tier is the natural upgrade, no code rewrite required,
// just swap the readDB/writeDB functions).

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || "changeme-set-a-real-key";
const DATA_DIR = path.join(__dirname, "data");
const VIOLATIONS_FILE = path.join(DATA_DIR, "violations.json");
const ACTIONS_FILE = path.join(DATA_DIR, "actions.json");

const MAX_VIOLATIONS_STORED = 5000;
const ACTION_RESEND_AFTER_MS = 60 * 1000; // if a "sent" action isn't acked in 60s, resend it

// ---------------------------------------------------------------
// tiny JSON-file storage helpers
// ---------------------------------------------------------------
function ensureDataFiles() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(VIOLATIONS_FILE)) fs.writeFileSync(VIOLATIONS_FILE, "[]");
  if (!fs.existsSync(ACTIONS_FILE)) fs.writeFileSync(ACTIONS_FILE, "[]");
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
// auth — every /api route (except /api/health) needs X-API-Key
// ---------------------------------------------------------------
function requireApiKey(req, res, next) {
  const key = req.header("X-API-Key");
  if (!key || key !== API_KEY) {
    return res.status(401).json({ error: "Invalid or missing X-API-Key header." });
  }
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

  const violations = readJSON(VIOLATIONS_FILE);
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
app.post("/api/actions", requireApiKey, (req, res) => {
  const { type, userId, username, reason } = req.body || {};
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

  res.json(due.map(({ id, type, userId, reason }) => ({ id, type, userId, reason })));
});

// Roblox -> here, after executing an action.
app.post("/api/actions/ack", requireApiKey, (req, res) => {
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
app.get("/api/actions", requireApiKey, (req, res) => {
  const actions = readJSON(ACTIONS_FILE).slice().reverse();
  res.json(actions.slice(0, 200));
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
