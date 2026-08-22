# Sentinel — Roblox Moderation Panel

An API + dashboard that receives anti-cheat violations from your Roblox game
(via the `Adminhandler` script), lets your moderators look up players, queue
ban/kick/unban actions the game server executes automatically, and jump
straight into Studio or the exact live server a flagged player is in.

```
Roblox game  --POST violation-->  this API  <--reads--  dashboard (public/)
Roblox game  <--polls pending actions--  this API  <--queues ban/kick--  dashboard
Dashboard  --looks up-->  Roblox Users API / (optional) Open Cloud Data Stores
```

## What's new in this version

- **Per-moderator logins** instead of one shared password. Every moderator
  gets their own username + key, so you can see who did what and revoke one
  person's access without rotating everyone else's key.
- **Open in Studio** and **Join Server** links, right from the dashboard —
  jump into the place in Studio, or deep-link into the exact live server
  instance a flagged player is in (from the `jobId` the anti-cheat reported).
- **Ban / Kick / Unban form** with username↔ID resolution, common ban
  reasons, internal notes, and a ban-length picker.
- **Lookup page** — pulls a player's public Roblox profile plus this panel's
  own ban/warning history, and (optionally) live in-game data straight from
  your DataStore.
- **Hardened auth**: hashed + timing-safe key comparisons, per-IP lockout
  after repeated bad keys, and rate limiting on every route.

## 1. Run it locally first (optional, 2 minutes)

```bash
npm install
GAME_API_KEY=some-long-random-string npm start
```

The console prints a bootstrap admin username + key on first boot — copy
that key now, it's only shown once (it's stored as a hash, not in plaintext).
Open `http://localhost:3000` and log in with it.

## 2. Deploy it for free — Render

1. Push this folder to a GitHub repo (Render deploys from GitHub/GitLab).
2. Go to [render.com](https://render.com) → **New +** → **Web Service** →
   connect your repo.
3. Settings:
   - **Build command:** `npm install`
   - **Start command:** `npm start`
   - **Instance type:** Free
4. Under **Environment**, add:

   | Variable | Required | What it's for |
   |---|---|---|
   | `GAME_API_KEY` | yes | Shared secret between this API and your Roblox game server. Generate with `openssl rand -hex 24`. Don't reuse a password you use elsewhere. |
   | `ADMIN_USERNAME` / `ADMIN_KEY` | recommended | Controls the bootstrap admin account instead of a random one being generated at boot. |
   | `PLACE_ID` | for Studio/join links | The Roblox place ID this panel moderates. Powers "Open in Studio" and "Join Server". |
   | `UNIVERSE_ID` | optional | Needed only for the Open Cloud game-data lookup below. |
   | `GAME_NAME` | optional | Cosmetic, shown on the Settings page. |
   | `OPEN_CLOUD_API_KEY`, `DATASTORE_NAME`, `DATASTORE_KEY_TEMPLATE` | optional | See "Live game data" below. |
   | `ALLOWED_ORIGIN` | optional | Only set this if you need to call the API from a different domain than the dashboard itself. Leave unset otherwise — it's more locked down that way. |

5. Deploy. Render gives you a URL like `https://your-app-name.onrender.com`.
6. Open it, check the Render logs for the bootstrap admin key, and log in.
   Add the rest of your moderators from **Settings → Moderators** — each
   person gets their own key, shown once, that they should store somewhere
   like a password manager.

### About data persistence
Violations, actions, and moderator accounts are stored in JSON files on
disk. Render's free tier disk is **not guaranteed to survive a redeploy**
(moderator accounts included — if that happens, the server will re-print a
fresh bootstrap admin on next boot). Once this matters to you, swap
`readJSON`/`writeJSON` in `server.js` for a free hosted Postgres like
[Supabase](https://supabase.com) or [Neon](https://neon.tech) — the rest of
the API doesn't need to change.

## 3. Wire up Roblox (anti-cheat + actions)

In `ServerScriptService.Adminhandler`, find the "DISCORD WEBHOOK + MODERATION
PANEL API" section and fill in:

```lua
local MODERATION_API_BASE = "https://your-app-name.onrender.com" -- your Render URL, no trailing slash
local MODERATION_API_KEY = "the-same-GAME_API_KEY-you-set-on-render"
```

Make sure **HttpService → Allow HTTP Requests** is enabled in Studio's Game
Settings. For the anti-cheat's violation reports to include working "Join
Server" links, make sure the payload it POSTs to `/api/violations` includes
`jobId` (`game.JobId`) and, ideally, `placeId` (`game.PlaceId`) — most
anti-cheat scripts already have both on hand when they report a flag.

That's it — violations show up on the dashboard, the heartbeat dot next to
the Sentinel logo turns green once the anti-cheat has reported recently, and
any Ban/Kick queued in the panel gets executed in-game within ~10 seconds.

## 4. Open in Studio / Join Server

- **Open in Studio** (top bar + Settings page) opens `PLACE_ID` for editing
  in Roblox Studio — useful for jumping straight from a moderation report
  into the place itself.
- **Join Server** (on each violation row, and on a looked-up user if they
  have a recent flagged session) deep-links into the *exact live server*
  the flagged player is in, using the `roblox://experiences/start` protocol
  with the violation's `placeId`/`jobId`. Requires the Roblox client and
  that you have permission to join that server.

## 5. Live game data (optional)

The Lookup page can show whatever your game stores about a player —
currency, XP, private servers, whatever — by reading straight from a Roblox
**Open Cloud Data Store** entry. This is generic: the dashboard renders
whatever keys your DataStore entry has, so there's nothing to hardcode.

1. Create an Open Cloud API key in the [Creator
   Dashboard](https://create.roblox.com/dashboard/credentials) scoped to
   **Data Stores → Read** for your experience's universe.
2. Set on Render:
   - `OPEN_CLOUD_API_KEY` — the key from step 1.
   - `UNIVERSE_ID` — your experience's universe ID (not the place ID).
   - `DATASTORE_NAME` — the DataStore name your game already writes player
     data to.
   - `DATASTORE_KEY_TEMPLATE` (optional, default `{userId}`) — how your game
     builds entry keys, e.g. `Player_{userId}` or `PlayerData-{userId}`.
3. Redeploy. The Lookup page will now show a "Live Game Data" card for any
   player it can find an entry for.

If this isn't configured, the Lookup page just skips that card — everything
else still works.

## Security

- Every moderator has their **own key** (Settings → Moderators, admin only);
  revoking one person never affects anyone else.
- The game server's `GAME_API_KEY` is completely separate from moderator
  keys and is never exposed to the browser.
- Keys are stored hashed (SHA-256) and compared with a timing-safe
  comparison, not `===`.
- Repeated invalid keys from the same address are locked out for 5 minutes;
  every route is additionally rate-limited.
- `helmet` sets standard security headers; no CORS headers are sent unless
  you explicitly set `ALLOWED_ORIGIN`, so the API can't be read from a
  random other website by default.
- The last remaining admin account can't be deleted, so you can't
  accidentally lock yourself out.

## API reference

Game routes require `X-API-Key: <GAME_API_KEY>`. Dashboard routes require
`X-Mod-Key: <a moderator's personal key>`; routes marked *(admin)* also
require that moderator's role to be `admin`.

| Method | Path                       | Called by | Purpose                                            |
|--------|----------------------------|-----------|-----------------------------------------------------|
| GET    | `/api/health`              | anyone    | Unauthenticated liveness check                      |
| POST   | `/api/violations`          | Roblox    | Log a new anti-cheat violation                      |
| GET    | `/api/violations`          | Dashboard | List violations (`?userId=&severity=&search=&limit=`) |
| POST   | `/api/actions`             | Dashboard | Queue `{type: ban\|kick\|unban, userId, reason, notes, banLength}` |
| GET    | `/api/actions/pending`     | Roblox    | Poll for actions to execute                         |
| POST   | `/api/actions/ack`         | Roblox    | Acknowledge a completed action                       |
| GET    | `/api/actions`             | Dashboard | Recent action history (`?userId=`)                  |
| GET    | `/api/heartbeat`           | Dashboard | Last time the game reported a violation / polled actions |
| GET    | `/api/me`                  | Dashboard | Confirms your key, returns your identity + config    |
| GET    | `/api/moderators`          | Dashboard *(admin)* | List moderators                            |
| POST   | `/api/moderators`          | Dashboard *(admin)* | Add a moderator, returns their key once    |
| DELETE | `/api/moderators/:id`      | Dashboard *(admin)* | Revoke a moderator                         |
| GET    | `/api/lookup/roblox`       | Dashboard | Resolve `?username=` or `?userId=` + merge mod history |
| GET    | `/api/lookup/gamedata/:id` | Dashboard | Live DataStore entry for a player (if configured)    |
