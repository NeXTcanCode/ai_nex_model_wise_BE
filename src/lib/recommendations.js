import crypto from "node:crypto";

export const maxPrompt = Number(process.env.MAX_PROMPT_CHARACTERS || 20000);
export const userModels = (models, userId) => models.find({ userId });
export const now = () => new Date().toISOString();
export const sanitize = (s) => String(s).replace(/(?:sk-|api[_-]?key\s*[:=]|password\s*[:=]|token\s*[:=])[^\s,;]+/gi, "[redacted]");
export const promptHash = (s) => crypto.createHash("sha256").update(s).digest("hex");
export const estimateTokens = (text) => Math.ceil(text.length / 4);

const textOf = (prompt, context = {}) => `${prompt} ${context.contextDetails || ""}`.toLowerCase();
export const assess = (prompt, context = {}) => {
  const text = textOf(prompt, context);
  const taskType = /code|debug|program|api|software/.test(text) ? "coding" : /write|rewrite|email|story|copy/.test(text) ? "writing" : /analy|compare|research|reason|why/.test(text) ? "analysis" : "general";
  const reasoningRequirement = /complex|architecture|debug|research|analy|multi-step/.test(text) ? "high" : "medium";
  return { taskDomain: taskType, taskType, complexity: reasoningRequirement === "high" ? "complex" : "moderate", reasoningRequirement, contextRequirement: context.hasContext ? "provided" : "none", precisionRequirement: "medium", riskLevel: "low" };
};
export const fitsAssessment = (model, assessment) => model.isActive !== false && (!assessment || assessment.reasoningRequirement !== "high" || !/mini|haiku|flash/i.test(model.displayName));
export const rankModels = (models, assessment) => [...models].sort((a, b) => {
  const priceA = a.inputPricePerMillion == null ? Number.POSITIVE_INFINITY : a.inputPricePerMillion;
  const priceB = b.inputPricePerMillion == null ? Number.POSITIVE_INFINITY : b.inputPricePerMillion;
  const lightweightA = /mini|haiku|flash/i.test(a.displayName) ? 1 : 0;
  const lightweightB = /mini|haiku|flash/i.test(b.displayName) ? 1 : 0;
  return assessment?.reasoningRequirement === "high" ? lightweightA - lightweightB || priceA - priceB : priceA - priceB;
});
export const choose = (models, assessment) => rankModels(models, assessment)[0];
