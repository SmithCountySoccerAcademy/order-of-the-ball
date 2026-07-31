const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DATA_PATH =
  process.env.LEADERBOARD_PATH ||
  path.join(__dirname, "..", "data", "leaderboard.json");

const MAX_NAME = 24;
const MAX_ENTRIES_RETURN = 25;
const MIN_SUBMIT_INTERVAL_MS = 30 * 1000; // soft rate limit per player

function ensureFile() {
  const dir = path.dirname(DATA_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DATA_PATH)) {
    fs.writeFileSync(DATA_PATH, JSON.stringify({ players: {} }, null, 2));
  }
}

function read() {
  ensureFile();
  try {
    return JSON.parse(fs.readFileSync(DATA_PATH, "utf8"));
  } catch {
    return { players: {} };
  }
}

function write(data) {
  ensureFile();
  fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2), "utf8");
}

function sanitizeName(name) {
  return String(name || "Knight")
    .replace(/[<>]/g, "")
    .trim()
    .slice(0, MAX_NAME) || "Knight";
}

function sanitizeEmblem(emblem) {
  const e = String(emblem || "⚔️").slice(0, 8);
  return e || "⚔️";
}

function rankFromAuraClient(aura, rank) {
  const r = Number(rank);
  if (Number.isFinite(r) && r >= 1 && r <= 99) return Math.floor(r);
  const a = Number(aura) || 0;
  // Rough fallback if client omits rank
  return Math.min(99, Math.max(1, Math.floor(Math.sqrt(a / 50)) + 1));
}

/**
 * Upsert a player score. playerId is a client-generated UUID stored locally.
 */
function submitScore({
  playerId,
  name,
  emblem,
  aura,
  rank,
  streak,
  bestStreak,
}) {
  const id = String(playerId || "").trim().slice(0, 64);
  if (!id || id.length < 8) {
    const err = new Error("Missing player id");
    err.statusCode = 400;
    throw err;
  }

  const auraN = Math.max(0, Math.floor(Number(aura) || 0));
  const streakN = Math.max(0, Math.floor(Number(streak) || 0));
  const bestN = Math.max(streakN, Math.floor(Number(bestStreak) || 0));
  const rankN = rankFromAuraClient(auraN, rank);

  const data = read();
  const prev = data.players[id];
  const now = Date.now();

  if (prev && prev.updatedAt && now - prev.updatedAt < MIN_SUBMIT_INTERVAL_MS) {
    // Allow read-back without error flood — return current board entry
    return { entry: prev, throttled: true };
  }

  // Only allow aura to go up (anti-cheat lite); name/emblem can update
  const nextAura = prev ? Math.max(prev.aura || 0, auraN) : auraN;
  const nextBest = prev
    ? Math.max(prev.bestStreak || 0, bestN)
    : bestN;
  const nextStreak = streakN;
  const nextRank = Math.max(prev?.rank || 1, rankN);

  const entry = {
    playerId: id,
    name: sanitizeName(name),
    emblem: sanitizeEmblem(emblem),
    aura: nextAura,
    rank: nextRank,
    streak: nextStreak,
    bestStreak: nextBest,
    updatedAt: now,
  };

  data.players[id] = entry;
  write(data);
  return { entry, throttled: false };
}

function getBoard(limit = 15) {
  const data = read();
  const list = Object.values(data.players || {});
  list.sort(
    (a, b) =>
      b.aura - a.aura ||
      b.rank - a.rank ||
      b.bestStreak - a.bestStreak ||
      (a.name || "").localeCompare(b.name || "")
  );
  return list.slice(0, Math.min(MAX_ENTRIES_RETURN, limit)).map((p, i) => ({
    place: i + 1,
    name: p.name,
    emblem: p.emblem,
    aura: p.aura,
    rank: p.rank,
    streak: p.streak,
    bestStreak: p.bestStreak,
    playerId: p.playerId,
  }));
}

function newPlayerId() {
  return crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
}

module.exports = {
  submitScore,
  getBoard,
  newPlayerId,
  DATA_PATH,
};
