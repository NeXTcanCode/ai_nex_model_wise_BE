export const USAGE_LIMITS = Object.freeze({
  weeklyUnits: 40_000,
  dailyUnits: 12_000,
  maxInputTokens: 8_000,
  // requestsPerMinute: 2,
  // requestsPerDay: 15,
  // requestsPerWeek: 50,
  outputModes: Object.freeze({
    concise: Object.freeze({
      maxOutputTokens: 800,
      instruction: "Answer directly and briefly.",
    }),
    standard: Object.freeze({
      maxOutputTokens: 1_500,
      instruction: "Provide a clear, balanced response.",
    }),
    detailed: Object.freeze({
      maxOutputTokens: 4_000,
      instruction: "Provide a comprehensive response with relevant detail.",
    }),
  }),
});

export const estimateTokens = (value) =>
  Math.max(1, Math.ceil(String(value || "").length / 4));

export const weightedUnits = (inputTokens, outputTokens) =>
  Math.max(0, Number(inputTokens) || 0) +
  Math.max(0, Number(outputTokens) || 0) * 2;

export const outputMode = (value) =>
  USAGE_LIMITS.outputModes[value] ? value : "standard";

export const usageSummary = (events, at = Date.now()) => {
  const minuteCutoff = at - 60_000;
  const dayCutoff = at - 24 * 60 * 60 * 1000;
  const weekCutoff = at - 7 * 24 * 60 * 60 * 1000;
  const recent = events.filter(
    (event) => new Date(event.createdAt).getTime() >= weekCutoff
  );
  const weeklyUnits = recent.reduce(
    (total, event) => total + (event.weightedUnits || 0),
    0
  );
  const daily = recent.filter(
    (event) => new Date(event.createdAt).getTime() >= dayCutoff
  );
  const minute = recent.filter(
    (event) => new Date(event.createdAt).getTime() >= minuteCutoff
  );
  const dailyUnits = daily.reduce(
    (total, event) => total + (event.weightedUnits || 0),
    0
  );
  const resetAt = recent.length
    ? new Date(
        Math.min(
          ...recent.map((event) => new Date(event.createdAt).getTime())
        ) +
          7 * 24 * 60 * 60 * 1000
      ).toISOString()
    : null;

  return {
    usedUnits: weeklyUnits,
    limitUnits: USAGE_LIMITS.weeklyUnits,
    percent: Math.min(
      100,
      Math.round((weeklyUnits / USAGE_LIMITS.weeklyUnits) * 100)
    ),
    dailyUsedUnits: dailyUnits,
    dailyLimitUnits: USAGE_LIMITS.dailyUnits,
    requestsThisMinute: minute.length,
    requestsToday: daily.length,
    requestsThisWeek: recent.length,
    resetAt,
  };
};

export const quotaError = ({ summary, estimatedInputTokens }) => {
  if (estimatedInputTokens > USAGE_LIMITS.maxInputTokens)
    return `This prompt exceeds the ${USAGE_LIMITS.maxInputTokens.toLocaleString()} token input limit.`;
  if (summary.usedUnits + estimatedInputTokens > USAGE_LIMITS.weeklyUnits)
    return `Weekly usage limit reached: ${USAGE_LIMITS.weeklyUnits.toLocaleString()} weighted units. Your allowance resets automatically.`;
  // if (summary.dailyUsedUnits + estimatedInputTokens > USAGE_LIMITS.dailyUnits)
  //   return `Daily usage limit reached: ${USAGE_LIMITS.dailyUnits.toLocaleString()} weighted units. Longer prompts and responses use more units.`;
  // if (summary.requestsThisMinute >= USAGE_LIMITS.requestsPerMinute)
  //   return `Message speed limit reached: up to ${USAGE_LIMITS.requestsPerMinute} messages per minute. Please wait a moment and try again.`;
  // if (summary.requestsToday >= USAGE_LIMITS.requestsPerDay)
  //   return `Daily message limit reached: up to ${USAGE_LIMITS.requestsPerDay} messages per day.`;
  // if (summary.requestsThisWeek >= USAGE_LIMITS.requestsPerWeek)
  //   return `Weekly message limit reached: up to ${USAGE_LIMITS.requestsPerWeek} messages per week. Your allowance resets automatically.`;
  return null;
};
