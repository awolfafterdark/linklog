import { Elysia } from "elysia";
import { randomBytes, randomInt, createHmac, timingSafeEqual } from "node:crypto";

// Server-side first-party challenge: the answer is never included in the token.
const secret = randomBytes(32);
const challenges = new Map();
const lifetimeMs = 5 * 60 * 1000;
const maxChallenges = 10000;
const sign = (value) => createHmac("sha256", secret).update(value).digest("hex");
const purge = () => {
  const now = Date.now();
  for (const [nonce, challenge] of challenges) {
    if (challenge.expires <= now) challenges.delete(nonce);
  }
};

export function verifyChallenge(token, answer) {
  if (typeof token !== "string" || typeof answer !== "string" || token.length > 150) return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [nonce, expires, mac] = parts;
  if (!/^[a-f0-9]{32}$/.test(nonce) || !/^\d{13}$/.test(expires) || !/^[a-f0-9]{64}$/.test(mac)) return false;
  const expected = sign(nonce + "." + expires);
  if (!timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return false;
  const challenge = challenges.get(nonce);
  if (!challenge || challenge.expires !== Number(expires)) return false;
  // Consume the challenge even if the answer is wrong.
  challenges.delete(nonce);
  if (challenge.expires <= Date.now()) return false;
  return answer.trim() === challenge.answer;
}

export const capRoutes = new Elysia({ prefix: "/cap" })
  .get("/challenge", () => {
    purge();
    if (challenges.size >= maxChallenges) {
      return { error: "Too many pending challenges. Try again shortly." };
    }
    const a = randomInt(2, 15), b = randomInt(2, 15);
    const nonce = randomBytes(16).toString("hex");
    const expires = Date.now() + lifetimeMs;
    challenges.set(nonce, { answer: String(a + b), expires });
    const payload = nonce + "." + expires;
    return { question: "What is " + a + " + " + b + "?", token: payload + "." + sign(payload) };
  });
