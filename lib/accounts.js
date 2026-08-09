const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DATA_PATH =
  process.env.ACCOUNTS_PATH ||
  path.join(__dirname, "..", "data", "accounts.json");

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  process.env.UNLOCK_SECRET ||
  process.env.STRIPE_SECRET_KEY ||
  "dev-only-insecure-session-secret";

const SESSION_DAYS = Number(process.env.SESSION_DAYS || 60);
const MIN_USER = 3;
const MAX_USER = 20;
const PIN_MIN = 4;
const PIN_MAX = 6;

function ensureFile() {
  const dir = path.dirname(DATA_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DATA_PATH)) {
    fs.writeFileSync(
      DATA_PATH,
      JSON.stringify({ users: {} }, null, 2),
      "utf8"
    );
  }
}

function read() {
  ensureFile();
  try {
    const data = JSON.parse(fs.readFileSync(DATA_PATH, "utf8"));
    if (!data.users || typeof data.users !== "object") data.users = {};
    return data;
  } catch {
    return { users: {} };
  }
}

function write(data) {
  ensureFile();
  fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2), "utf8");
}

function normalizeUsername(raw) {
  return String(raw || "")
    .trim()
    .replace(/\s+/g, "")
    .slice(0, MAX_USER);
}

function usernameKey(username) {
  return normalizeUsername(username).toLowerCase();
}

function validateUsername(username) {
  const u = normalizeUsername(username);
  if (u.length < MIN_USER || u.length > MAX_USER) {
    return {
      ok: false,
      error: `Username must be ${MIN_USER}–${MAX_USER} characters`,
    };
  }
  if (!/^[a-zA-Z0-9_]+$/.test(u)) {
    return {
      ok: false,
      error: "Use letters, numbers, and underscores only",
    };
  }
  return { ok: true, username: u };
}

function validatePin(pin) {
  const p = String(pin || "").trim();
  if (!/^\d+$/.test(p) || p.length < PIN_MIN || p.length > PIN_MAX) {
    return {
      ok: false,
      error: `PIN must be ${PIN_MIN}–${PIN_MAX} digits`,
    };
  }
  return { ok: true, pin: p };
}

function hashPin(pin) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(String(pin), salt, 32).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPin(pin, stored) {
  if (!stored || !String(stored).includes(":")) return false;
  const [salt, hash] = String(stored).split(":");
  if (!salt || !hash) return false;
  try {
    const next = crypto.scryptSync(String(pin), salt, 32).toString("hex");
    const a = Buffer.from(hash, "hex");
    const b = Buffer.from(next, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function b64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function sign(payloadB64) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payloadB64)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function createSessionToken(username) {
  const exp = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  const payload = b64url(
    JSON.stringify({
      v: 1,
      product: "order-of-the-ball",
      u: usernameKey(username),
      exp,
    })
  );
  return `${payload}.${sign(payload)}`;
}

function verifySessionToken(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) {
    return { ok: false, error: "Not signed in" };
  }
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return { ok: false, error: "Invalid session" };

  const expected = sign(payload);
  try {
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return { ok: false, error: "Invalid session" };
    }
  } catch {
    return { ok: false, error: "Invalid session" };
  }

  try {
    const json = JSON.parse(
      Buffer.from(
        payload.replace(/-/g, "+").replace(/_/g, "/"),
        "base64"
      ).toString("utf8")
    );
    if (json.product !== "order-of-the-ball" || !json.u) {
      return { ok: false, error: "Invalid session" };
    }
    if (json.exp && Date.now() > Number(json.exp)) {
      return { ok: false, error: "Session expired — sign in again" };
    }
    return { ok: true, usernameKey: String(json.u) };
  } catch {
    return { ok: false, error: "Invalid session" };
  }
}

function publicUser(user) {
  if (!user) return null;
  return {
    username: user.username,
    updatedAt: user.updatedAt || null,
    hasCharacter: Boolean(user.character && user.character.name),
  };
}

function register({ username, pin, character, unlockToken }) {
  const uCheck = validateUsername(username);
  if (!uCheck.ok) {
    const err = new Error(uCheck.error);
    err.statusCode = 400;
    throw err;
  }
  const pCheck = validatePin(pin);
  if (!pCheck.ok) {
    const err = new Error(pCheck.error);
    err.statusCode = 400;
    throw err;
  }

  const key = usernameKey(uCheck.username);
  const data = read();
  if (data.users[key]) {
    const err = new Error("That username is taken — try another");
    err.statusCode = 409;
    throw err;
  }

  const now = new Date().toISOString();
  const user = {
    username: uCheck.username,
    pinHash: hashPin(pCheck.pin),
    createdAt: now,
    updatedAt: now,
    character:
      character && typeof character === "object" && character.name
        ? character
        : null,
    unlockToken: unlockToken ? String(unlockToken).slice(0, 2000) : "",
  };
  data.users[key] = user;
  write(data);

  return {
    token: createSessionToken(uCheck.username),
    user: publicUser(user),
    character: user.character,
    unlockToken: user.unlockToken || null,
  };
}

function login({ username, pin }) {
  const uCheck = validateUsername(username);
  if (!uCheck.ok) {
    const err = new Error(uCheck.error);
    err.statusCode = 400;
    throw err;
  }
  const pCheck = validatePin(pin);
  if (!pCheck.ok) {
    const err = new Error(pCheck.error);
    err.statusCode = 400;
    throw err;
  }

  const key = usernameKey(uCheck.username);
  const data = read();
  const user = data.users[key];
  if (!user || !verifyPin(pCheck.pin, user.pinHash)) {
    const err = new Error("Wrong username or PIN");
    err.statusCode = 401;
    throw err;
  }

  return {
    token: createSessionToken(user.username),
    user: publicUser(user),
    character: user.character || null,
    unlockToken: user.unlockToken || null,
  };
}

function getUserByKey(key) {
  const data = read();
  return data.users[key] || null;
}

function getCharacter(usernameKeyVal) {
  const user = getUserByKey(usernameKeyVal);
  if (!user) {
    const err = new Error("Account not found");
    err.statusCode = 404;
    throw err;
  }
  return {
    user: publicUser(user),
    character: user.character || null,
    unlockToken: user.unlockToken || null,
    updatedAt: user.updatedAt || null,
  };
}

function saveCharacter(usernameKeyVal, { character, unlockToken }) {
  if (!character || typeof character !== "object" || !character.name) {
    const err = new Error("Character data is missing");
    err.statusCode = 400;
    throw err;
  }

  const data = read();
  const user = data.users[usernameKeyVal];
  if (!user) {
    const err = new Error("Account not found");
    err.statusCode = 404;
    throw err;
  }

  user.character = character;
  user.updatedAt = new Date().toISOString();
  if (unlockToken) {
    user.unlockToken = String(unlockToken).slice(0, 2000);
  }
  data.users[usernameKeyVal] = user;
  write(data);

  return {
    user: publicUser(user),
    character: user.character,
    unlockToken: user.unlockToken || null,
    updatedAt: user.updatedAt,
  };
}

function authFromRequest(req) {
  const header = req.headers.authorization || "";
  let token = "";
  if (header.toLowerCase().startsWith("bearer ")) {
    token = header.slice(7).trim();
  } else {
    token = String(req.body?.sessionToken || req.headers["x-session-token"] || "").trim();
  }
  return verifySessionToken(token);
}

module.exports = {
  register,
  login,
  getCharacter,
  saveCharacter,
  authFromRequest,
  verifySessionToken,
  validateUsername,
  validatePin,
};
