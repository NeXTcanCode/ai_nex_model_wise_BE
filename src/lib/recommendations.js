import crypto from "node:crypto";

export const maxPrompt = Number(process.env.MAX_PROMPT_CHARACTERS || 20000);
export const userModels = (models, userId) => models.find({ userId });
export const now = () => new Date().toISOString();
export const sanitize = (s) => String(s).replace(/(?:sk-|api[_-]?key\s*[:=]|password\s*[:=]|token\s*[:=])[^\s,;]+/gi, "[redacted]");
export const promptHash = (s) => crypto.createHash("sha256").update(s).digest("hex");
export const estimateTokens = (text) => Math.ceil(text.length / 4);
