import { estimateTokens } from "../usage/quota.js";

const ALLOWED_ROLES = new Set(["user", "assistant"]);
const MAX_MESSAGES = 40;

const cleanMessage = (message) => {
  const role = String(message?.role || "").toLowerCase();
  const content = String(message?.content || "").trim();
  if (!ALLOWED_ROLES.has(role) || !content) return null;
  return { role, content };
};

export const buildConversationContext = (messages, latestPrompt) => {
  const cleaned = Array.isArray(messages)
    ? messages.slice(-MAX_MESSAGES).map(cleanMessage).filter(Boolean)
    : [];
  const prompt = String(latestPrompt || "").trim();

  // The latest prompt is authoritative. Add it when an older frontend does not
  // send a messages array, or when it is not already the final user message.
  const last = cleaned.at(-1);
  if (!last || last.role !== "user" || last.content !== prompt) {
    cleaned.push({ role: "user", content: prompt });
  }

  const estimatedInputTokens = cleaned.reduce(
    (total, message) => total + estimateTokens(message.content),
    0
  );
  return { messages: cleaned, estimatedInputTokens };
};
