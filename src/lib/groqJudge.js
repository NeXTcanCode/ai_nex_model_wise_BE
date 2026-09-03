import { sanitize, estimateTokens } from "./recommendations.js";

const TASK_TYPES = ["coding", "writing", "analysis", "general"];
const REASONING_LEVELS = ["low", "medium", "high"];
const CONTEXT_LEVELS = ["small", "provided", "medium", "large"];
const PRECISION_LEVELS = ["medium", "high"];
const RISK_LEVELS = ["low", "medium", "high"];
const GOAL_CLARITY = ["clear", "implicit"];

const clamp = (value, minimum, maximum) =>
  Math.min(maximum, Math.max(minimum, value));

const oneOf = (value, allowed) =>
  typeof value === "string" && allowed.includes(value) ? value : null;

const SYSTEM_PROMPT = `You judge a single user prompt for an AI model routing system. Read the prompt and output STRICT JSON ONLY (no prose, no markdown fences) with exactly these fields:
{
  "taskType": one of ${JSON.stringify(TASK_TYPES)},
  "reasoningRequirement": one of ${JSON.stringify(REASONING_LEVELS)},
  "contextRequirement": one of ${JSON.stringify(CONTEXT_LEVELS)},
  "precisionRequirement": one of ${JSON.stringify(PRECISION_LEVELS)},
  "riskLevel": one of ${JSON.stringify(RISK_LEVELS)},
  "requiresVision": boolean,
  "goalClarity": one of ${JSON.stringify(GOAL_CLARITY)},
  "evidenceStrength": number between 0 and 1 (your confidence in this judgment)
}
Judge the actual content and difficulty of the prompt, not keywords it contains. Do not answer the prompt.`;

class GroqJudgeError extends Error {}

const parseJudgeJson = (raw) => {
  const text = String(raw || "").trim();
  const withoutFences = text.replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
  try {
    return JSON.parse(withoutFences);
  } catch {
    throw new GroqJudgeError("Groq judge returned non-JSON output.");
  }
};

const validateJudgment = (parsed) => {
  const taskType = oneOf(parsed.taskType, TASK_TYPES);
  const reasoningRequirement = oneOf(parsed.reasoningRequirement, REASONING_LEVELS);
  const contextRequirement = oneOf(parsed.contextRequirement, CONTEXT_LEVELS);
  const precisionRequirement = oneOf(parsed.precisionRequirement, PRECISION_LEVELS);
  const riskLevel = oneOf(parsed.riskLevel, RISK_LEVELS);
  const goalClarity = oneOf(parsed.goalClarity, GOAL_CLARITY);
  const requiresVision = typeof parsed.requiresVision === "boolean" ? parsed.requiresVision : null;
  const evidenceStrength = Number.isFinite(Number(parsed.evidenceStrength))
    ? clamp(Number(parsed.evidenceStrength), 0, 1)
    : null;

  if (
    !taskType ||
    !reasoningRequirement ||
    !contextRequirement ||
    !precisionRequirement ||
    !riskLevel ||
    !goalClarity ||
    requiresVision === null ||
    evidenceStrength === null
  ) {
    throw new GroqJudgeError("Groq judge output failed schema validation.");
  }

  return {
    taskType,
    reasoningRequirement,
    contextRequirement,
    precisionRequirement,
    riskLevel,
    goalClarity,
    requiresVision,
    evidenceStrength,
  };
};

export const judgeWithGroq = async (prompt, context = {}) => {
  if (!process.env.GROQ_API_KEY || process.env.GROQ_API_KEY.startsWith("replace-")) {
    throw new GroqJudgeError("GROQ_NOT_CONFIGURED");
  }

  const redactedPrompt = sanitize(String(prompt || ""));
  const contextNote = context.hasContext
    ? `Attached context type: ${context.contextType || "other"}.`
    : "No additional context attached.";

  const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
    },
    body: JSON.stringify({
      model: process.env.GROQ_OPTIMIZER_MODEL || process.env.GROQ_MODEL,
      temperature: 0.1,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: `${contextNote}\n\nPrompt:\n${redactedPrompt}` },
      ],
    }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new GroqJudgeError(data.error?.message || "Groq judge request failed.");
  }

  const parsed = parseJudgeJson(data.choices?.[0]?.message?.content);
  const judged = validateJudgment(parsed);

  const inputTokens = estimateTokens(`${prompt} ${context.contextDetails || ""}`);
  const contextRequirement =
    inputTokens >= 3500
      ? "large"
      : inputTokens >= 1200
      ? "medium"
      : context.hasContext
      ? "provided"
      : judged.contextRequirement === "large" || judged.contextRequirement === "medium"
      ? "small"
      : judged.contextRequirement;

  return {
    taskDomain: judged.taskType === "coding" ? "software_engineering" : judged.taskType,
    taskType: judged.taskType,
    complexity:
      judged.reasoningRequirement === "high"
        ? "complex"
        : judged.reasoningRequirement === "medium"
        ? "moderate"
        : "simple",
    reasoningRequirement: judged.reasoningRequirement,
    contextRequirement,
    precisionRequirement: judged.precisionRequirement,
    riskLevel: judged.riskLevel,
    contextType: String(context.contextType || "none").toLowerCase(),
    requiresVision: judged.requiresVision || String(context.contextType || "").toLowerCase() === "image",
    goalClarity: judged.goalClarity,
    estimatedInputTokens: inputTokens,
    evidenceStrength: Number(judged.evidenceStrength.toFixed(2)),
    judgeSource: "groq",
  };
};

export { GroqJudgeError };
