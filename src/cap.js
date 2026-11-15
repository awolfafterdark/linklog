import { Elysia } from "elysia";
import { randomBytes, randomInt, createHmac, timingSafeEqual } from "node:crypto";

// First-party, single-use arithmetic challenge. No external CAPTCHA provider.
const secret = randomBytes(32);
const used = new Map();
const lifetimeMs = 5 * 60 * 1000;
const sign = (value) => createHmac("sha256", secret).update(value).digest("hex");

export function verifyChallenge(token, answer) {
  if (typeof token !== "string" || typeof answer !== "string" || token.length > 300) return false;
  const parts = token.split(".");
  if (parts.length !== 4) return false;
  const [nonce, sum, expires, mac] = parts;
  if (!/^[a-f0-9]{32}$/.test(nonce) || !/^\d{1,3}$/.test(sum) || !/^\d{13}$/.test(expires) || !/^[a-f0-9]{64}$/.test(mac)) return false;
  const expected = sign(nonce + "." + sum + "." + expires);
  if (!timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return false;
  const now = Date.now();
  if (Number(expires) < now || Number(expires) > now + lifetimeMs || used.has(nonce)) return false;
  if (answer.trim() !== sum) return false;
  used.set(nonce, Number(expires));
  for (const [id, expiry] of used) if (expiry < now) used.delete(id);
  return true;
}

export const capRoutes = new Elysia({ prefix: "/cap" })
  .get("/challenge", () => {
    const a = randomInt(2, 15), b = randomInt(2, 15);
    const nonce = randomBytes(16).toString("hex");
    const sum = String(a + b), expires = String(Date.now() + lifetimeMs);
    const payload = nonce + "." + sum + "." + expires;
    return { question: "What is " + a + " + " + b + "?", token: payload + "." + sign(payload) };
  });
