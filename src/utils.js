import { randomInt } from "node:crypto";

export const generateString = (length) => {
  const characters = "abcdefghijklmnopqrstuvwxyz1234567890";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += characters[randomInt(characters.length)];
  }
  return result;
};

export const generateUniqueId = (checkFunction) => {
  const id = generateString(5);
  if (checkFunction(id)) {
    return generateUniqueId(checkFunction);
  }
  return id;
};

export const validateUrl = (value) => {
  if (typeof value !== "string" || value.length > 1000) return false;
  try {
    const parsed = new URL(value);
    if (!["http:", "https:"].includes(parsed.protocol)) return false;
    if (!parsed.hostname || parsed.username || parsed.password) return false;
    return true;
  } catch {
    return false;
  }
};

export const tryAsync = async (fn) => {
  try {
    return await fn();
  } catch {
    return null;
  }
};
