import { estimateTokens, USAGE_LIMITS } from "../usage/quota.js";

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

  const latestPromptTokens = estimateTokens(prompt);
  if (latestPromptTokens > USAGE_LIMITS.maxInputTokens) {
    return {
      messages: [{ role: "user", content: prompt }],
      estimatedInputTokens: latestPromptTokens,
    };
  }

  const selected = [];
  let usedTokens = 0;
  for (let index = cleaned.length - 1; index >= 0; index -= 1) {
    const message = cleaned[index];
    const tokens = estimateTokens(message.content);
    if (usedTokens + tokens > USAGE_LIMITS.maxInputTokens) break;
    selected.unshift(message);
    usedTokens += tokens;
  }

  return { messages: selected, estimatedInputTokens: usedTokens };
};
