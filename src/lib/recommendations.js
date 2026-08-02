import crypto from "node:crypto";

export const maxPrompt = Number(process.env.MAX_PROMPT_CHARACTERS || 20000);
export const userModels = (models, userId) => models.find({ userId });
export const now = () => new Date().toISOString();
export const sanitize = (s) => String(s).replace(/(?:sk-|api[_-]?key\s*[:=]|password\s*[:=]|token\s*[:=])[^\s,;]+/gi, "[redacted]");
export const promptHash = (s) => crypto.createHash("sha256").update(s).digest("hex");
export const estimateTokens = (text) => Math.ceil(text.length / 4);

export function assess(prompt, context) {
  const text = prompt.toLowerCase(), tokens = estimateTokens(prompt);
  let level = tokens <= 100 ? "low" : tokens <= 1000 ? "medium" : "high";
  const complex = /architect|race condition|debug|refactor|migrate|security|research|compare|design/.test(text);
  if (complex && level === "low") level = "medium";
  if (complex && level === "medium") level = "high";
  return {
    taskDomain: /code|function|bug|api|jwt/.test(text) ? "software_engineering" : /summar|rewrite|email|write/.test(text) ? "writing" : "general_reasoning",
    tokenCount: tokens,
    taskType: level === "high" ? "complex_problem_solving" : "standard_task",
    complexity: level,
    reasoningRequirement: level,
    contextRequirement: context?.hasContext ? context.contextType === "multiple_files" || context.codeLineRange === "above_1500" ? "large" : "medium" : "none",
    precisionRequirement: level,
    riskLevel: /legal|medical|security/.test(text) ? "high" : "low",
  };
}

export const choose = (models, assessment) => {
  const score = (model) => {
    const name = model.displayName.toLowerCase();
    let value = 0;
    if (/haiku|mini|flash|instant|8b|small/.test(name)) value += assessment.complexity === "low" ? 5 : assessment.complexity === "medium" ? 2 : -5;
    if (/sonnet|standard|pro|70b|120b/.test(name)) value += assessment.complexity === "high" ? 5 : assessment.complexity === "medium" ? 3 : 0;
    if (/opus|ultra|o1|reasoning/.test(name)) value += assessment.riskLevel === "high" || assessment.complexity === "high" ? 4 : -6;
    if (assessment.contextRequirement === "large" && /haiku|mini|flash|instant|8b/.test(name)) value -= 3;
    return value;
  };
  return [...models].sort((a, b) => score(b) - score(a))[0];
};

export const fitsAssessment = (model, assessment) => choose([model], assessment) === model;

export const rankModels = (models, assessment, feedback = {}) => {
  const score = (model) => {
    const name = model.displayName.toLowerCase();
    let value = 0;
    if (/haiku|mini|flash|instant|8b|small/.test(name)) value += assessment.complexity === "low" ? 5 : assessment.complexity === "medium" ? 2 : -5;
    if (/sonnet|standard|pro|70b|120b/.test(name)) value += assessment.complexity === "high" ? 5 : assessment.complexity === "medium" ? 3 : 0;
    if (/opus|ultra|o1|reasoning/.test(name)) value += assessment.riskLevel === "high" || assessment.complexity === "high" ? 4 : -6;
    if (assessment.contextRequirement === "large" && /haiku|mini|flash|instant|8b/.test(name)) value -= 3;
    if (model.isActive === false) value -= 100;
    if (feedback[model.id]?.liked) value += 2;
    if (feedback[model.id]?.rejected) value -= 2;
    if (model.inputPricePerMillion != null) value -= Math.min(4, model.inputPricePerMillion / 10);
    return value;
  };
  return [...models].sort((a, b) => score(b) - score(a));
};
