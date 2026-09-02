import crypto from "node:crypto";

export const userModels = (models, userId) => models.find({ userId });
export const now = () => new Date().toISOString();
export const sanitize = (value) =>
  String(value).replace(
    /(?:sk-|api[_-]?key\s*[:=]|password\s*[:=]|token\s*[:=])[^\s,;]+/gi,
    "[redacted]"
  );
export const promptHash = (value) =>
  crypto.createHash("sha256").update(value).digest("hex");

// Tokenizers differ between providers. This is deliberately an estimate and is
// only used for relative context/cost calculations.
export const estimateTokens = (text) => Math.max(1, Math.ceil(String(text).length / 4));

const clamp = (value, minimum, maximum) =>
  Math.min(maximum, Math.max(minimum, value));
const normalizedText = (prompt, context = {}) =>
  `${prompt} ${context.contextType || ""} ${context.contextDetails || ""}`.toLowerCase();
const occurrences = (text, expression) => (text.match(expression) || []).length;

export const assess = (prompt, context = {}) => {
  const text = normalizedText(prompt, context);
  const contextType = String(context.contextType || "none").toLowerCase();
  const intentWindow = `${String(prompt).slice(0, 600)} ${String(prompt).slice(-300)}`.toLowerCase();
  const hasExplicitGoal = /(?:\?|\b(?:please|review|find|fix|explain|implement|build|create|summarize|analy[sz]e|compare|refactor|identify|recommend|help me|why|how)\b)/.test(
    intentWindow
  );
  const inputTokens = estimateTokens(`${prompt} ${context.contextDetails || ""}`);
  const codeStructureCount = occurrences(
    text,
    /(?:=>|\b(?:const|let|var|function|class|import|export|async|await|try|catch)\b|[{};])/g
  );
  const codingSignal =
    /\b(?:code|debug|program|api|software|database|mongodb|sql|function|repository|server|frontend|backend)\b/.test(
      text
    ) || codeStructureCount >= 4;
  const writingSignal =
    /\b(?:write|rewrite|draft|summarize|translate|email|story|copy|article|tone|grammar|proofread)\b/.test(
      text
    );
  const analysisSignal =
    /\b(?:analy[sz]e?|compare|research|reason|evaluate|investigate|explain|why|how)\b/.test(
      text
    ) || contextType === "data_or_table";

  const taskType = codingSignal
    ? "coding"
    : writingSignal
    ? "writing"
    : analysisSignal
    ? "analysis"
    : "general";

  let complexityPoints = 0;
  if (
    /\b(?:architecture|multi[- ]?(?:file|step)|race condition|root cause|security|authentication|migration|production|performance|refactor|debug|research|complex)\b/.test(
      text
    )
  )
    complexityPoints += 3;
  if (inputTokens >= 3500) complexityPoints += 3;
  else if (inputTokens >= 1500) complexityPoints += 2;
  else if (inputTokens >= 600) complexityPoints += 1;
  if (codeStructureCount >= 35) complexityPoints += 2;
  else if (codeStructureCount >= 12) complexityPoints += 1;
  if (Boolean(context.hasContext)) complexityPoints += 1;
  if (/\b(?:across|interactions?|dependencies|trade-?offs?|constraints?)\b/.test(text))
    complexityPoints += 1;

  const reasoningRequirement =
    complexityPoints >= 5 ? "high" : complexityPoints >= 2 ? "medium" : "low";
  const precisionRequirement = /\b(?:security|auth|database|financial|medical|legal|exact|production|test|verify)\b/.test(
    text
  )
    ? "high"
    : reasoningRequirement === "high"
    ? "high"
    : "medium";
  const riskLevel = /\b(?:medical|legal|financial|security|production|data loss|authentication)\b/.test(
    text
  )
    ? "high"
    : precisionRequirement === "high"
    ? "medium"
    : "low";
  const contextRequirement =
    inputTokens >= 3500
      ? "large"
      : inputTokens >= 1200
      ? "medium"
      : context.hasContext
      ? "provided"
      : "small";
  const evidenceStrength = clamp(
    0.25 +
      (taskType !== "general" ? 0.15 : 0) +
      (complexityPoints ? 0.1 : 0) +
      (inputTokens >= 600 ? 0.05 : 0) +
      (precisionRequirement === "high" ? 0.1 : 0) +
      (context.hasContext ? 0.05 : 0) +
      (hasExplicitGoal ? 0.2 : 0),
    0.25,
    0.9
  );

  return {
    taskDomain: taskType === "coding" ? "software_engineering" : taskType,
    taskType,
    complexity:
      reasoningRequirement === "high"
        ? "complex"
        : reasoningRequirement === "medium"
        ? "moderate"
        : "simple",
    reasoningRequirement,
    contextRequirement,
    precisionRequirement,
    riskLevel,
    contextType,
    requiresVision: contextType === "image",
    goalClarity: hasExplicitGoal ? "clear" : "implicit",
    estimatedInputTokens: inputTokens,
    evidenceStrength: Number(evidenceStrength.toFixed(2)),
  };
};

const modelProfile = (model) => {
  const text = `${model.displayName || ""} ${model.openRouterModelId || ""}`.toLowerCase();
  const verySmall = /\b(?:nano|tiny)\b/.test(text);
  const lightweight = /\b(?:flash|haiku|mini|lite|small|instant)\b/.test(text);
  const premiumReasoner = /\b(?:opus|max|ultra|reasoning|thinking|o[134]|r1)\b/.test(text);
  const strongGeneral = /\b(?:sonnet|pro|gpt[- ]?5|gpt[- ]?4(?:\.1)?|claude|gemini)\b/.test(
    text
  );
  const codeSpecialist = /\b(?:coder|codestral|devstral|deepseek|code)\b/.test(text);
  const multimodal = /\b(?:vision|image|multimodal|omni|gpt[- ]?4o|gemini)\b/.test(text);

  let tier = 3;
  if (premiumReasoner) tier = 4.8;
  else if (strongGeneral) tier = 4.2;
  if (lightweight) tier = Math.min(tier, 2.4);
  if (verySmall) tier = 1.6;

  return {
    tier,
    lightweight,
    codeSpecialist,
    multimodal,
    certainty:
      verySmall || lightweight || premiumReasoner || strongGeneral || codeSpecialist
        ? 0.85
        : 0.45,
  };
};

const requirementTier = { low: 1.8, medium: 3, high: 4.2 };
const weightsFor = (assessment) => {
  if (assessment.reasoningRequirement === "high")
    return { capability: 55, domain: 15, context: 12, reliability: 13, cost: 5 };
  if (assessment.reasoningRequirement === "low")
    return { capability: 35, domain: 15, context: 8, reliability: 12, cost: 30 };
  return { capability: 45, domain: 15, context: 10, reliability: 15, cost: 15 };
};

const capabilityFit = (tier, requiredTier) =>
  tier >= requiredTier
    ? clamp(0.92 + (tier - requiredTier) * 0.04, 0, 1)
    : clamp(1 - (requiredTier - tier) * 0.42, 0.08, 1);

const costScores = (models) => {
  const known = models
    .map((model) => Number(model.inputPricePerMillion))
    .filter((price, index) => modelHasPrice(models[index]) && Number.isFinite(price) && price >= 0);
  if (!known.length) return new Map(models.map((model) => [model.id, 0.5]));

  const minimum = Math.min(...known);
  const maximum = Math.max(...known);
  return new Map(
    models.map((model) => {
      if (!modelHasPrice(model)) return [model.id, 0.25];
      const price = Number(model.inputPricePerMillion);
      if (!Number.isFinite(price) || price < 0) return [model.id, 0.25];
      if (maximum === minimum) return [model.id, 0.75];
      const scaled = (Math.log1p(maximum) - Math.log1p(price)) /
        (Math.log1p(maximum) - Math.log1p(minimum));
      return [model.id, clamp(scaled, 0, 1)];
    })
  );
};

const modelHasPrice = (model) =>
  model.inputPricePerMillion !== null &&
  model.inputPricePerMillion !== undefined &&
  model.inputPricePerMillion !== "";

const estimatedCost = (model, inputTokens) => {
  if (!modelHasPrice(model)) return null;
  const price = Number(model.inputPricePerMillion);
  if (!Number.isFinite(price) || price < 0) return null;
  return (inputTokens * price) / 1_000_000;
};

const reasonsFor = (model, profile, assessment, scoreParts, costPosition) => {
  const reasons = [];
  const required = requirementTier[assessment.reasoningRequirement] || requirementTier.medium;
  if (assessment.goalClarity === "implicit")
    reasons.push(
      "This is a broad prompt, so the ranking is a best-effort estimate rather than a task-specific match."
    );
  if (profile.tier + 0.2 >= required) {
    reasons.push(
      `Its name and available metadata suggest capability suitable for ${assessment.reasoningRequirement}-reasoning work.`
    );
  } else {
    reasons.push(
      `The available model metadata does not strongly support ${assessment.reasoningRequirement}-reasoning work.`
    );
  }
  if (assessment.taskType === "coding") {
    reasons.push(
      profile.codeSpecialist
        ? "Its model name suggests a coding-oriented strength for this software task."
        : "No coding-specific metadata was found, so its general capability is being used for this software task."
    );
  } else if (profile.lightweight) {
    reasons.push("Its lightweight variant is suitable when speed and cost matter.");
  }
  if (assessment.requiresVision)
    reasons.push(
      profile.multimodal
        ? "Its model family indicates support for multimodal work."
        : "No multimodal capability could be inferred from the available model metadata."
    );
  if (assessment.contextRequirement === "large" && profile.lightweight)
    reasons.push("A lightweight variant is penalized for the larger supplied prompt.");
  if (costPosition >= 0.8) reasons.push("It has one of the lowest known input prices in this shortlist.");
  else if (!modelHasPrice(model)) reasons.push("Pricing is unavailable, so the cost comparison is incomplete.");
  if (profile.certainty < 0.6)
    reasons.push("Capability metadata is limited, so this score should be treated as a heuristic.");

  return reasons.slice(0, 3);
};

export const rankModels = (models, assessment, options = {}) => {
  const activeModels = models.filter((model) => model.isActive !== false);
  const inputTokens = Number.isFinite(options.inputTokens)
    ? Math.max(0, options.inputTokens)
    : Math.max(0, assessment.estimatedInputTokens || 0);
  const weights = weightsFor(assessment);
  const costs = costScores(activeModels);
  const required = requirementTier[assessment.reasoningRequirement] || requirementTier.medium;

  return activeModels
    .map((model) => {
      const profile = modelProfile(model);
      const capability = capabilityFit(profile.tier, required);
      const domain =
        assessment.taskType === "coding"
          ? profile.codeSpecialist
            ? 1
            : clamp(0.58 + profile.tier * 0.08, 0, 0.94)
          : assessment.requiresVision
          ? profile.multimodal
            ? 1
            : 0.35
          : profile.lightweight
          ? 0.78
          : 0.9;
      const context =
        assessment.contextRequirement === "large"
          ? clamp(0.3 + profile.tier * 0.15, 0, 1)
          : assessment.contextRequirement === "medium"
          ? clamp(0.5 + profile.tier * 0.11, 0, 1)
          : 0.9;
      const reliability =
        assessment.precisionRequirement === "high"
          ? clamp(0.2 + profile.tier * 0.17, 0, 1)
          : clamp(0.52 + profile.tier * 0.1, 0, 1);
      const cost = costs.get(model.id) ?? 0.25;
      const scoreParts = { capability, domain, context, reliability, cost };
      const score = Object.entries(weights).reduce(
        (total, [key, weight]) => total + scoreParts[key] * weight,
        0
      );
      return {
        id: model.id,
        rank: 0,
        name: model.displayName,
        displayName: model.displayName,
        providerName: model.providerName || null,
        score: Number(score.toFixed(1)),
        inputPricePerMillion: modelHasPrice(model)
          ? Number(model.inputPricePerMillion)
          : null,
        estimatedInputCostUsd: estimatedCost(model, inputTokens),
        reasons: reasonsFor(model, profile, assessment, scoreParts, cost),
        profileCertainty: profile.certainty,
      };
    })
    .sort((a, b) => {
      const scoreDifference = b.score - a.score;
      if (scoreDifference) return scoreDifference;
      const priceA = a.inputPricePerMillion ?? Number.POSITIVE_INFINITY;
      const priceB = b.inputPricePerMillion ?? Number.POSITIVE_INFINITY;
      if (priceA !== priceB) return priceA - priceB;
      const nameDifference = String(a.displayName).localeCompare(String(b.displayName));
      return nameDifference || String(a.id).localeCompare(String(b.id));
    })
    .map((model, index) => ({ ...model, rank: index + 1 }));
};

export const recommendationConfidence = (ranking, assessment) => {
  if (!ranking.length) return 0;
  const topQuality = clamp(ranking[0].score / 100, 0, 1);
  const evidence = clamp(Number(assessment.evidenceStrength) || 0.35, 0, 1);
  const certainty = clamp(Number(ranking[0].profileCertainty) || 0.45, 0, 1);

  if (ranking.length === 1)
    return Number(clamp(0.45 + topQuality * 0.14 + evidence * 0.08, 0.5, 0.68).toFixed(3));

  const margin = clamp((ranking[0].score - ranking[1].score) / 35, 0, 1);
  const confidence = clamp(
    0.3 + topQuality * 0.2 + margin * 0.3 + evidence * 0.1 + certainty * 0.1,
    0.5,
    0.95
  );
  const evidenceCeiling = 0.62 + evidence * 0.38;
  return Number(Math.min(confidence, evidenceCeiling).toFixed(3));
};

// Kept for callers that only need eligibility/one winner.
export const fitsAssessment = (model) => model.isActive !== false;
export const choose = (models, assessment, options) =>
  rankModels(models, assessment, options)[0] || null;
