require("dotenv").config();

const path = require("path");
const express = require("express");
const cors = require("cors");
const Stripe = require("stripe");
const {
  createUnlockToken,
  verifyUnlockToken,
  redeemAccessCode,
} = require("./lib/unlock");
const leaderboard = require("./lib/leaderboard");

const app = express();
const PORT = process.env.PORT || 8787;

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

const PUBLIC_APP_URL = (
  process.env.PUBLIC_APP_URL || `http://localhost:${PORT}`
).replace(/\/$/, "");

// Empty string in Render becomes 0 with Number("") — treat blank as default $20
const STRIPE_PRICE_ID = (process.env.STRIPE_PRICE_ID || "").trim();
const _priceRaw = process.env.PRICE_CENTS;
const PRICE_CENTS =
  _priceRaw === undefined || String(_priceRaw).trim() === ""
    ? 2000
    : Number(_priceRaw);

const corsOrigins = String(process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.set("trust proxy", 1);

app.use(
  cors({
    origin(origin, cb) {
      // Allow same-origin tools, mobile apps, and configured GH Pages origins
      if (!origin) return cb(null, true);
      if (!corsOrigins.length) return cb(null, true);
      if (corsOrigins.includes(origin)) return cb(null, true);
      // Allow any github.io preview under configured hosts
      try {
        const host = new URL(origin).hostname;
        if (host.endsWith(".github.io")) return cb(null, true);
        if (host === "localhost" || host === "127.0.0.1") return cb(null, true);
      } catch {
        /* ignore */
      }
      return cb(new Error("Not allowed by CORS"));
    },
  })
);

app.use(express.json());

// Local / Render: serve the static app too
app.use(express.static(path.join(__dirname)));

app.get("/api/health", (_req, res) => {
  const priceConfigured =
    Boolean(STRIPE_PRICE_ID) ||
    (Number.isFinite(PRICE_CENTS) && PRICE_CENTS > 0);
  res.json({
    ok: true,
    product: "order-of-the-ball",
    stripe: Boolean(stripe),
    priceConfigured,
    priceMode: STRIPE_PRICE_ID ? "stripe_price_id" : "price_cents",
    priceCents: STRIPE_PRICE_ID ? null : PRICE_CENTS,
    appUrl: PUBLIC_APP_URL,
  });
});

app.post("/api/create-checkout-session", async (req, res) => {
  if (!stripe) {
    return res.status(503).json({
      error: "Stripe is not configured. Set STRIPE_SECRET_KEY on the server.",
    });
  }

  try {
    const lineItem = STRIPE_PRICE_ID
      ? { price: STRIPE_PRICE_ID, quantity: 1 }
      : {
          price_data: {
            currency: "usd",
            unit_amount: PRICE_CENTS,
            product_data: {
              name: "Order of the Ball",
              description:
                "Lifetime access · ball mastery training · one ball · 5×5",
            },
          },
          quantity: 1,
        };

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: [lineItem],
      success_url: `${PUBLIC_APP_URL}/?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${PUBLIC_APP_URL}/?checkout=cancel`,
      metadata: {
        product: "order-of-the-ball",
      },
      payment_intent_data: {
        metadata: { product: "order-of-the-ball" },
      },
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Checkout failed" });
  }
});

/**
 * After Stripe redirects back with session_id, the app calls this once.
 * We verify payment and return a lifetime unlock token.
 */
app.post("/api/verify-session", async (req, res) => {
  if (!stripe) {
    return res.status(503).json({ error: "Stripe is not configured." });
  }

  const sessionId = String(req.body?.sessionId || "").trim();
  if (!sessionId.startsWith("cs_")) {
    return res.status(400).json({ error: "Missing or invalid session id" });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (session.metadata?.product && session.metadata.product !== "order-of-the-ball") {
      return res.status(400).json({ error: "Unexpected product" });
    }

    if (session.payment_status !== "paid" && session.status !== "complete") {
      return res.status(402).json({ error: "Payment not completed" });
    }

    const email =
      session.customer_details?.email ||
      session.customer_email ||
      "";

    const token = createUnlockToken({ email, source: "stripe" });
    res.json({
      unlocked: true,
      token,
      email: email || null,
    });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message || "Could not verify session" });
  }
});

app.post("/api/verify-token", (req, res) => {
  const result = verifyUnlockToken(req.body?.token);
  if (!result.ok) {
    return res.status(401).json({ unlocked: false, error: result.error });
  }
  res.json({ unlocked: true, claims: result.claims });
});

app.post("/api/redeem-code", (req, res) => {
  const result = redeemAccessCode(req.body?.code);
  if (!result.ok) {
    return res.status(400).json({ error: result.error });
  }
  res.json({ unlocked: true, token: result.token });
});

// —— Live leaderboard (opt-in submit from Arena) ——
app.get("/api/leaderboard", (req, res) => {
  try {
    const limit = Math.min(25, Math.max(5, Number(req.query.limit) || 15));
    res.json({
      ok: true,
      updatedAt: Date.now(),
      board: leaderboard.getBoard(limit),
    });
  } catch (err) {
    res.status(500).json({ error: err.message || "Leaderboard failed" });
  }
});

app.post("/api/leaderboard/submit", (req, res) => {
  try {
    // Prefer unlocked buyers; still allow submit if token missing for beta UX
    const token = req.body?.unlockToken || req.headers["x-unlock-token"];
    if (token) {
      const v = verifyUnlockToken(token);
      if (!v.ok) {
        return res.status(401).json({ error: "Unlock required to join the Arena" });
      }
    }

    const result = leaderboard.submitScore({
      playerId: req.body?.playerId,
      name: req.body?.name,
      emblem: req.body?.emblem,
      aura: req.body?.aura,
      rank: req.body?.rank,
      streak: req.body?.streak,
      bestStreak: req.body?.bestStreak,
    });

    res.json({
      ok: true,
      throttled: result.throttled,
      entry: result.entry,
      board: leaderboard.getBoard(15),
    });
  } catch (err) {
    res.status(err.statusCode || 500).json({
      error: err.message || "Submit failed",
    });
  }
});

app.listen(PORT, () => {
  console.log(`Order of the Ball API + app at http://localhost:${PORT}`);
  console.log(`PUBLIC_APP_URL=${PUBLIC_APP_URL}`);
  if (!stripe) {
    console.warn("STRIPE_SECRET_KEY not set — checkout disabled.");
  } else {
    const mode = process.env.STRIPE_SECRET_KEY.startsWith("sk_live_")
      ? "LIVE"
      : "TEST";
    console.log(`Stripe mode: ${mode}`);
  }
  if (!process.env.UNLOCK_SECRET) {
    console.warn(
      "UNLOCK_SECRET not set — using fallback. Set a strong secret in production."
    );
  }
  console.log(`Leaderboard data → ${leaderboard.DATA_PATH}`);
});
