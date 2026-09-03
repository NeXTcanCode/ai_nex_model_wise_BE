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

// Incremental counterpart to isSafetyClassificationOnly() for use while a
// response is still streaming in. A response can only be proven safety-label-only
// once the stream ends (all lines matched); it can be proven NOT safety-only as
// soon as a single disqualifying line is seen, so text can be released early.
export const createSafetyGate = () => {
  let buffer = "";
  let pendingLine = "";
  let matchedLines = 0;
  let released = false;

  const testLine = (raw) => {
    const line = raw.trim().replace(/^[-*]\s*/, "");
    if (!line) return true;
    return SAFETY_LABEL_LINE.test(line);
  };

  const disqualify = () => {
    released = true;
    const remaining = buffer;
    buffer = "";
    return remaining;
  };

  return {
    // Feed the next chunk of streamed text. Returns the text (if any) that is
    // now safe to forward to the client.
    feed(delta) {
      if (released) return delta;
      buffer += delta;
      pendingLine += delta;
      let idx;
      while ((idx = pendingLine.indexOf("\n")) !== -1) {
        const line = pendingLine.slice(0, idx);
        pendingLine = pendingLine.slice(idx + 1);
        if (line.trim()) {
          if (testLine(line)) {
            matchedLines += 1;
            if (matchedLines > 4) return disqualify();
          } else {
            return disqualify();
          }
        }
      }
      return "";
    },
    // Call once the stream has ended. Returns whether the full response was
    // safety-label-only, plus any buffered text still owed to the client.
    finish() {
      if (released) return { isSafetyOnly: false, remaining: "" };
      if (pendingLine.trim()) {
        if (!testLine(pendingLine)) {
          return { isSafetyOnly: false, remaining: disqualify() };
        }
        matchedLines += 1;
      }
      if (matchedLines > 0 && matchedLines <= 4) {
        released = true;
        return { isSafetyOnly: true, remaining: "" };
      }
      return { isSafetyOnly: false, remaining: disqualify() };
    },
  };
};
