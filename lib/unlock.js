const crypto = require("crypto");

const UNLOCK_SECRET =
  process.env.UNLOCK_SECRET ||
  process.env.STRIPE_SECRET_KEY ||
  "dev-only-insecure-unlock-secret";

function b64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function b64urlJson(obj) {
  return b64url(JSON.stringify(obj));
}

function sign(payloadB64) {
  return crypto
    .createHmac("sha256", UNLOCK_SECRET)
    .update(payloadB64)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/** Lifetime unlock token (no expiry). */
function createUnlockToken({ email = "", source = "stripe" } = {}) {
  const payload = b64urlJson({
    v: 1,
    product: "order-of-the-ball",
    lifetime: true,
    email: String(email || "").slice(0, 120),
    source,
    iat: Date.now(),
  });
  return `${payload}.${sign(payload)}`;
}

function verifyUnlockToken(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) {
    return { ok: false, error: "Invalid token" };
  }
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return { ok: false, error: "Invalid token" };

  const expected = sign(payload);
  try {
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return { ok: false, error: "Invalid token signature" };
    }
  } catch {
    return { ok: false, error: "Invalid token" };
  }

  try {
    const json = JSON.parse(
      Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString(
        "utf8"
      )
    );
    if (json.product !== "order-of-the-ball" || !json.lifetime) {
      return { ok: false, error: "Wrong product token" };
    }
    return { ok: true, claims: json };
  } catch {
    return { ok: false, error: "Invalid token payload" };
  }
}

function accessCodes() {
  return String(process.env.ACCESS_CODES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function redeemAccessCode(code) {
  const normalized = String(code || "").trim();
  if (!normalized) return { ok: false, error: "Enter an access code" };
  const list = accessCodes();
  if (!list.length) {
    return { ok: false, error: "Access codes are not enabled" };
  }
  const match = list.find((c) => c.toLowerCase() === normalized.toLowerCase());
  if (!match) return { ok: false, error: "Invalid access code" };
  return {
    ok: true,
    token: createUnlockToken({ source: "access_code", email: "" }),
  };
}

module.exports = {
  createUnlockToken,
  verifyUnlockToken,
  redeemAccessCode,
  accessCodes,
};
