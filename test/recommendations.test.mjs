import test from "node:test";
import assert from "node:assert/strict";
import {
  assess,
  rankModels,
  recommendationConfidence,
} from "../src/lib/recommendations.js";
import { app, db } from "../src/server.js";

const flash = {
  id: "flash",
  displayName: "DeepSeek V4 Flash",
  providerName: "DeepSeek",
  inputPricePerMillion: 0.09,
  isActive: true,
};
const sonnet = {
  id: "sonnet",
  displayName: "Claude Sonnet 4.6",
  providerName: "Anthropic",
  inputPricePerMillion: 3,
  isActive: true,
};

const complexCode = `
  import express from "express";
  export async function connectDatabase(config) {
    try {
      const app = express();
      await Promise.all(config.services.map(async (service) => {
        await service.connect();
      }));
      return app;
    } catch (error) {
      throw new Error(error.message);
    }
  }
`.repeat(55);

test("long structured code is assessed as high reasoning without magic keywords", () => {
  const assessment = assess(complexCode, { hasContext: false });
  assert.equal(assessment.taskType, "coding");
  assert.equal(assessment.reasoningRequirement, "high");
  assert.equal(assessment.contextRequirement, "large");
});

test("complex code ranks a stronger general model above a lightweight variant", () => {
  const assessment = assess(complexCode);
  const ranking = rankModels([flash, sonnet], assessment);
  assert.deepEqual(
    ranking.map((model) => model.id),
    ["sonnet", "flash"]
  );
  assert.ok(ranking[0].score > ranking[1].score);
  assert.equal(ranking[0].rank, 1);
  assert.ok(recommendationConfidence(ranking, assessment) > 0.7);
});

test("short simple work can favor a cheaper lightweight model", () => {
  const assessment = assess("Write a short, friendly greeting.");
  const ranking = rankModels([sonnet, flash], assessment);
  assert.equal(assessment.reasoningRequirement, "low");
  assert.equal(ranking[0].id, "flash");
});

test("candidate input order does not change the ranking", () => {
  const assessment = assess(complexCode);
  const forward = rankModels([flash, sonnet], assessment).map((model) => model.id);
  const reverse = rankModels([sonnet, flash], assessment).map((model) => model.id);
  assert.deepEqual(forward, reverse);
});

test("unknown models with missing prices use deterministic tie-breaking", () => {
  const assessment = assess("Summarize this note.");
  const models = [
    { id: "z", displayName: "Zulu Model", isActive: true },
    { id: "a", displayName: "Alpha Model", isActive: true },
  ];
  const ranking = rankModels(models, assessment);
  assert.deepEqual(
    ranking.map((model) => model.id),
    ["a", "z"]
  );
  for (const model of ranking) {
    assert.ok(Number.isFinite(model.score));
    assert.equal(model.estimatedInputCostUsd, null);
  }
});

test("zero price is valid and produces a zero estimated cost", () => {
  const assessment = assess("Write a title.");
  const ranking = rankModels(
    [
      { id: "free", displayName: "Quick Flash", inputPricePerMillion: 0 },
      { id: "paid", displayName: "Quick Lite", inputPricePerMillion: 1 },
    ],
    assessment
  );
  assert.equal(ranking[0].id, "free");
  assert.equal(ranking[0].estimatedInputCostUsd, 0);
});

test("confidence is finite, margin-sensitive, and limited for one candidate", () => {
  const assessment = assess(complexCode);
  const clearRanking = rankModels([flash, sonnet], assessment);
  const tiedRanking = rankModels(
    [
      { id: "a", displayName: "Unknown A" },
      { id: "b", displayName: "Unknown B" },
    ],
    assessment
  );
  const singleRanking = rankModels([sonnet], assessment);
  const clearConfidence = recommendationConfidence(clearRanking, assessment);
  const tiedConfidence = recommendationConfidence(tiedRanking, assessment);
  const singleConfidence = recommendationConfidence(singleRanking, assessment);

  assert.ok(Number.isFinite(clearConfidence));
  assert.ok(clearConfidence > tiedConfidence);
  assert.ok(singleConfidence >= 0.5 && singleConfidence <= 0.68);
});

test("an explicit task goal increases confidence without changing the score order", () => {
  const implicitAssessment = assess(complexCode);
  const clearAssessment = assess(`Review this code and identify reliability issues.\n${complexCode}`);
  const implicitRanking = rankModels([flash, sonnet], implicitAssessment);
  const clearRanking = rankModels([flash, sonnet], clearAssessment);

  assert.equal(implicitAssessment.goalClarity, "implicit");
  assert.equal(clearAssessment.goalClarity, "clear");
  assert.deepEqual(
    implicitRanking.map((model) => model.id),
    clearRanking.map((model) => model.id)
  );
  assert.ok(
    recommendationConfidence(clearRanking, clearAssessment) >
      recommendationConfidence(implicitRanking, implicitAssessment)
  );
});

test("inactive models are not ranked", () => {
  const assessment = assess("Write a title.");
  const ranking = rankModels([{ ...flash, isActive: false }, sonnet], assessment);
  assert.deepEqual(ranking.map((model) => model.id), ["sonnet"]);
});

test("recommendation API returns the winner, runner-up, confidence, and full ranking", async (t) => {
  db.users.length = 0;
  db.models.length = 0;
  db.recommendations.length = 0;
  const server = app.listen(0, "127.0.0.1");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await new Promise((resolve) => server.once("listening", resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  const request = async (path, options = {}) => {
    const response = await fetch(`${baseUrl}${path}`, {
      ...options,
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    });
    return { status: response.status, body: await response.json() };
  };

  const registration = await request("/api/v1/auth/register", {
    method: "POST",
    body: JSON.stringify({
      name: "Ranking Test",
      email: "ranking-test@example.com",
      password: "correct-horse-battery-staple",
    }),
  });
  assert.equal(registration.status, 201);
  const authorization = `Bearer ${registration.body.data.token}`;

  for (const model of [flash, sonnet]) {
    const created = await request("/api/v1/models", {
      method: "POST",
      headers: { Authorization: authorization },
      body: JSON.stringify(model),
    });
    assert.equal(created.status, 201);
  }

  const available = await request("/api/v1/models", {
    headers: { Authorization: authorization },
  });
  const candidates = available.body.data.models.filter((model) =>
    [flash.displayName, sonnet.displayName].includes(model.displayName)
  );
  const response = await request("/api/v1/recommendations", {
    method: "POST",
    headers: { Authorization: authorization },
    body: JSON.stringify({
      prompt: complexCode,
      candidateModelIds: candidates.map((model) => model.id),
      context: {
        hasContext: true,
        contextType: "code",
        contextDetails: "multiple files; api_key=secret-value",
      },
    }),
  });

  assert.equal(response.status, 201);
  const data = response.body.data;
  assert.equal(data.ranking.length, 2);
  assert.equal(data.recommendedModel.id, data.ranking[0].id);
  assert.equal(data.alternativeModel.id, data.ranking[1].id);
  assert.equal(data.ranking[0].displayName, sonnet.displayName);
  assert.ok(data.confidence > 0.7 && data.confidence <= 0.95);
  assert.ok(data.ranking.every((model) => Number.isFinite(model.score)));
  assert.ok(data.ranking.every((model) => !("profileCertainty" in model)));
  assert.equal(data.contextDetails, "multiple files; [redacted]");
});
