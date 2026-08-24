const SAFETY_LABEL_LINE =
  /^(?:user|response|assistant|prompt|content)\s+safety\s*:\s*(?:safe|unsafe|unknown|pass|passed)$/i;

export const isSafetyClassificationOnly = (value) => {
  const lines = String(value || "")
    .split(/\r?\n/)
    .map((line) => line.trim().replace(/^[-*]\s*/, ""))
    .filter(Boolean);

  return lines.length > 0 && lines.length <= 4 && lines.every((line) => SAFETY_LABEL_LINE.test(line));
};

export const NEXT_AI_RETRY_INSTRUCTION =
  "Respond as a conversational assistant. Answer the user's latest question directly. " +
  "Do not output moderation labels, safety classifications, or evaluator metadata.";

export const NEXT_AI_RESPONSE_FALLBACK =
  "I couldn't produce a useful response that time. Please try sending your message again.";
