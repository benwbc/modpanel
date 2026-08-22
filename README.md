# Sentinel — Roblox Moderation Panel

A tiny API + dashboard that receives anti-cheat violations from your Roblox
game (via the updated `Adminhandler` script) and lets you queue ban/kick/unban
actions that the game server picks up automatically.

```
Roblox game  --POST violation-->  this API  <--reads--  dashboard (public/)
Roblox game  <--polls pending actions--  this API  <--queues ban/kick--  dashboard
```

## 1. Run it locally first (optional, 2 minutes)

```bash
npm install
API_KEY=some-long-random-string npm start
```

Open `http://localhost:3000` and paste in the same `API_KEY` you set. You
should see an empty dashboard — that's correct, you haven't wired up Roblox yet.

## 2. Deploy it for free — Render

Render is currently the only mainstream host with a genuine no-credit-card
free tier for a Node web service (Railway/Fly.io no longer offer one). The
free tier **sleeps after 15 minutes of no traffic** and takes ~30–50s to wake
on the next request — fine for a hobby moderation panel; the Roblox polling
loop will just catch up on the next successful call.

1. Push this folder to a GitHub repo (Render deploys from GitHub/GitLab).
2. Go to [render.com](https://render.com) → sign up free (no card needed) →
   **New +** → **Web Service** → connect your repo.
3. Settings:
   - **Build command:** `npm install`
   - **Start command:** `npm start`
   - **Instance type:** Free
4. Under **Environment**, add a variable:
   - `API_KEY` = a long random string (e.g. generate one with
     `openssl rand -hex 24`). This is the shared secret both Roblox and the
     dashboard use — don't reuse a password you use elsewhere.
5. Deploy. Render gives you a URL like `https://your-app-name.onrender.com`.

### Since you have a `glow.sch.uk` email
That's a UK school address, so you likely qualify for the
[GitHub Student Developer Pack](https://education.github.com/pack) (verify
at education.github.com). It doesn't unlock a *better* free tier on Render
specifically, but it's worth activating anyway — it currently bundles free
credits/perks on things like Namecheap domains, JetBrains IDEs, and other
dev tools you may want later. For this project specifically, Render's free
tier alone is enough — no card, no student verification required.

### About data persistence
This starter stores violations/actions in JSON files on disk. Render's free
tier disk is **not guaranteed to survive a redeploy**. That's fine while
you're testing. Once this matters to you, swap `readJSON`/`writeJSON` in
`server.js` for a free hosted Postgres like [Supabase](https://supabase.com)
or [Neon](https://neon.tech) — the rest of the API doesn't need to change.

## 3. Wire up Roblox

In `ServerScriptService.Adminhandler`, find these two lines near the top of
the "DISCORD WEBHOOK + MODERATION PANEL API" section and fill them in:

```lua
local MODERATION_API_BASE = "https://your-app-name.onrender.com" -- your Render URL, no trailing slash
local MODERATION_API_KEY = "the-same-API_KEY-you-set-on-render"
```

Also make sure **HttpService → Allow HTTP Requests** is enabled in Studio's
Game Settings (it already is in this game — that's what the Discord webhook
uses).

That's it — violations will start appearing in the dashboard, and any
Ban/Kick you click there gets executed in-game within ~10 seconds.

## API reference

All routes except `/api/health` require header `X-API-Key: <your key>`.

| Method | Path                    | Called by | Purpose                                  |
|--------|-------------------------|-----------|-------------------------------------------|
| POST   | `/api/violations`       | Roblox    | Log a new violation                      |
| GET    | `/api/violations`       | Dashboard | List violations (`?userId=&severity=&search=&limit=`) |
| POST   | `/api/actions`          | Dashboard | Queue `{type: ban|kick|unban, userId, reason}` |
| GET    | `/api/actions/pending`  | Roblox    | Poll for actions to execute              |
| POST   | `/api/actions/ack`      | Roblox    | Acknowledge a completed action           |
| GET    | `/api/actions`          | Dashboard | Recent action history                    |
