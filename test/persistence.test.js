const test = require('node:test');
const assert = require('node:assert/strict');
const { hashPrompt, toRecommendationRecord } = require('../src/persistence/prompt');
const { createMemoryStore } = require('../src/persistence/memory-store');

test('hashes prompts without returning raw text', () => {
  const record = toRecommendationRecord({ prompt: 'secret prompt', recommendedModel: 'Model A' });
  assert.equal(record.promptHash, hashPrompt('secret prompt'));
  assert.equal('prompt' in record, false);
  assert.equal('rawPrompt' in toRecommendationRecord({ promptHash: 'x', rawPrompt: 'secret' }), false);
});

test('memory store provides persistence contract for local development', async () => {
  const store = createMemoryStore();
  await store.insert('recommendations', { promptHash: 'abc', promptSummary: 'summary' });
  assert.equal((await store.list('recommendations')).length, 1);
});
