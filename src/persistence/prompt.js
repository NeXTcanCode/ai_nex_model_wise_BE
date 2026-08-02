const crypto = require('node:crypto');

function hashPrompt(prompt) {
  if (typeof prompt !== 'string' || prompt.length === 0) throw new TypeError('prompt must be a non-empty string');
  return crypto.createHash('sha256').update(prompt, 'utf8').digest('hex');
}

function toRecommendationRecord(input) {
  const { prompt, ...safe } = input;
  if (prompt !== undefined) safe.promptHash = hashPrompt(prompt);
  if (!safe.promptHash) throw new TypeError('promptHash or prompt is required');
  delete safe.rawPrompt;
  delete safe.originalPrompt;
  return safe;
}

module.exports = { hashPrompt, toRecommendationRecord };
