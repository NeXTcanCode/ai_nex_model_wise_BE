import crypto from "node:crypto";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import "dotenv/config";
import mongoose from "mongoose";
import { connectMongo } from "./config/database.js";
import {
  users,
  models,
  recommendations,
  memory,
  setPersistence,
  id,
} from "./persistence.js";

const app = express();
const port = Number(process.env.PORT || 5001);
const sessions = new Map();
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_ORIGIN?.split(",") || ["https://model-wise.netlify.app"] }));
app.use(express.json({ limit: "1mb" }));
const error = (res, status, code, message, details = []) =>
  res
    .status(status)
    .json({ success: false, error: { code, message, details } });
const ok = (res, data, status = 200) =>
  res.status(status).json({ success: true, data });
const normalize = (s) =>
  String(s || "")
    .trim()
    .toLowerCase();
const now = () => new Date().toISOString();
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email });
const sanitize = (s) =>
  String(s).replace(
    /(?:sk-|api[_-]?key\s*[:=]|password\s*[:=]|token\s*[:=])[^\s,;]+/gi,
    "[redacted]"
  );
const promptHash = (s) => crypto.createHash("sha256").update(s).digest("hex");
const userModels = (userId) => models.find({ userId });
const removeLegacyIdIndexes = async () => {
  for (const collectionName of ["users", "usermodels", "recommendations"]) {
    try {
      await mongoose.connection.collection(collectionName).dropIndex("id_1");
      console.log(`Removed legacy ${collectionName}.id_1 index`);
    } catch (indexError) {
      if (indexError.codeName !== "IndexNotFound" && indexError.code !== 27) {
        throw indexError;
      }
    }
  }
};
const validateAuth = (body) => {
  const name = String(body.name || "").trim(),
    email = normalize(body.email),
    password = String(body.password || "");
  if (name && (name.length < 2 || name.length > 80))
    return "Name must be 2–80 characters.";
  if (!/^\S+@\S+\.\S+$/.test(email)) return "A valid email is required.";
  if (password.length < 8) return "Password must be at least 8 characters.";
  return null;
};
const issue = (user) => {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, user.id);
  return token;
};
async function auth(req, res, next) {
  const token = req.get("authorization")?.replace(/^Bearer\s+/i, "");
  const userId = token && sessions.get(token);
  const user = userId && (await users.findOne({ id: userId }));
  if (!user)
    return error(
      res,
      401,
      "UNAUTHORIZED",
      "A valid temporary session is required."
    );
  req.user = user;
  next();
}
const authPayload = (user) => ({
  user: publicUser(user),
  token: issue(user),
  authMode: "temporary-session",
});

app.get("/health", (_req, res) =>
  ok(res, {
    status: "ok",
    service: "ai-model-recommender-api",
    authMode: "temporary-session",
    persistence: mongoose.connection.readyState === 1 ? "mongodb" : "memory",
  })
);
app.post("/api/v1/auth/register", async (req, res, next) => {
  try {
    const invalid = validateAuth(req.body);
    if (invalid) return error(res, 400, "VALIDATION_ERROR", invalid);
    const email = normalize(req.body.email);
    if (await users.findOne({ email }))
      return error(
        res,
        409,
        "USER_ALREADY_EXISTS",
        "An account with that email already exists."
      );
    const user = await users.create({
      id: id(),
      name: String(req.body.name).trim(),
      email,
      password: String(req.body.password),
      createdAt: now(),
    });
    for (const [displayName, providerName] of [
      ["Claude Sonnet 4", "Anthropic"],
      ["GPT-4.1", "OpenAI"],
      ["Gemini 2.5 Pro", "Google"],
    ])
      await models.create({
        id: id(),
        userId: user.id,
        displayName,
        normalizedName: normalize(displayName),
        providerName,
        notes: "",
        isActive: true,
        source: "manual",
        createdAt: now(),
        updatedAt: now(),
      });
    return ok(res, authPayload(user), 201);
  } catch (e) {
    next(e);
  }
});
app.post("/api/v1/auth/login", async (req, res, next) => {
  try {
    const user = await users.findOne({
      email: normalize(req.body.email),
      password: String(req.body.password || ""),
    });
    if (!user)
      return error(
        res,
        401,
        "INVALID_CREDENTIALS",
        "Email or password is incorrect."
      );
    return ok(res, authPayload(user));
  } catch (e) {
    next(e);
  }
});
app.get("/api/v1/auth/me", auth, (req, res) =>
  ok(res, { user: publicUser(req.user), authMode: "temporary-session" })
);
app.post("/api/v1/auth/logout", (req, res) => {
  const token = req.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (token) sessions.delete(token);
  return ok(res, { loggedOut: true });
});

const modelSuggestions = [
  ["Claude Haiku", "Anthropic"],
  ["Claude Sonnet", "Anthropic"],
  ["Claude Opus", "Anthropic"],
  ["GPT Mini", "OpenAI"],
  ["GPT Standard", "OpenAI"],
  ["Gemini Flash", "Google"],
  ["Gemini Pro", "Google"],
  ["Llama 3.3 70B", "Meta"],
  ["DeepSeek R1", "DeepSeek"],
];
app.get("/api/v1/models", auth, async (req, res, next) => {
  try {
    return ok(res, { models: await userModels(req.user.id) });
  } catch (e) {
    next(e);
  }
});
app.post("/api/v1/models", auth, async (req, res, next) => {
  try {
    const displayName = String(req.body.displayName || "").trim();
    if (!displayName)
      return error(res, 400, "VALIDATION_ERROR", "Model name is required.");
    if (
      (await userModels(req.user.id)).some(
        (m) => m.normalizedName === normalize(displayName)
      )
    )
      return error(res, 409, "DUPLICATE_MODEL", "That model already exists.");
    const model = await models.create({
      id: id(),
      userId: req.user.id,
      displayName,
      normalizedName: normalize(displayName),
      providerName: req.body.providerName || null,
      inputPricePerMillion: req.body.inputPricePerMillion == null ? null : Number(req.body.inputPricePerMillion),
      outputPricePerMillion: req.body.outputPricePerMillion == null ? null : Number(req.body.outputPricePerMillion),
      pricingCurrency: req.body.pricingCurrency || "USD",
      notes: req.body.notes || "",
      isActive: true,
      source:
        req.body.source === "groq_suggestion" ? "groq_suggestion" : "manual",
      createdAt: now(),
      updatedAt: now(),
    });
    return ok(res, { model }, 201);
  } catch (e) {
    next(e);
  }
});
app.post("/api/v1/models/suggestions", auth, async (req, res, next) => {
  try {
    const q = normalize(req.body.query), words = q.split(/\s+/).filter(Boolean), headers = {};
    if (process.env.OPENROUTER_API_KEY && !process.env.OPENROUTER_API_KEY.startsWith("replace-")) headers.Authorization = `Bearer ${process.env.OPENROUTER_API_KEY}`;
    const response = await fetch("https://openrouter.ai/api/v1/models", { headers });
    if (!response.ok) return error(res, 502, "SUGGESTIONS_LOOKUP_FAILED", `OpenRouter returned ${response.status}.`);
    const data = await response.json();
    const suggestions = (data.data || [])
      .filter((model) => {
        const text = normalize(`${model.name} ${model.id} ${model.description || ""}`);
        return !words.length || words.every((word) => text.includes(word));
      })
      .slice(0, 5)
      .map((model) => ({ displayName: model.name, providerName: model.id.split("/")[0] || "Unknown" }));
    return ok(res, { suggestions });
  } catch (error) { next(error); }
});
app.post("/api/v1/models/pricing", auth, async (req, res, next) => {
  try {
    const query = normalize(req.body.query), words = query.split(/\s+/).filter(Boolean), headers = {};
    if (process.env.OPENROUTER_API_KEY && !process.env.OPENROUTER_API_KEY.startsWith("replace-")) headers.Authorization = `Bearer ${process.env.OPENROUTER_API_KEY}`;
    const response = await fetch("https://openrouter.ai/api/v1/models", { headers });
    if (!response.ok) return error(res, 502, "PRICING_LOOKUP_FAILED", `OpenRouter returned ${response.status}.`);
    const data = await response.json(), match = (data.data || []).find((model) => { const text = normalize(`${model.name} ${model.id}`); return words.every((word) => text.includes(word)); });
    return ok(res, { pricing: match?.pricing ? { inputPricePerMillion: Number(match.pricing.prompt) * 1000000, outputPricePerMillion: Number(match.pricing.completion) * 1000000, currency: "USD", source: "OpenRouter", modelId: match.id } : null });
  } catch (error) { next(error); }
});
async function getModel(req, res) {
  const m = (await userModels(req.user.id)).find(
    (x) => x.id === req.params.modelId
  );
  if (!m) {
    error(res, 404, "MODEL_NOT_FOUND", "Model not found.");
    return null;
  }
  return m;
}
app.patch("/api/v1/models/:modelId", auth, async (req, res, next) => {
  try {
    const m = await getModel(req, res);
    if (!m) return;
    if (req.body.displayName !== undefined) {
      const n = String(req.body.displayName).trim();
      if (!n)
        return error(res, 400, "VALIDATION_ERROR", "Model name is required.");
      if (
        (await userModels(req.user.id)).some(
          (x) => x.id !== m.id && x.normalizedName === normalize(n)
        )
      )
        return error(res, 409, "DUPLICATE_MODEL", "That model already exists.");
      m.displayName = n;
      m.normalizedName = normalize(n);
    }
    if (req.body.providerName !== undefined)
      m.providerName = req.body.providerName;
    if (req.body.notes !== undefined)
      m.notes = String(req.body.notes).slice(0, 300);
    m.updatedAt = now();
    await models.updateOne({ id: m.id }, { $set: m });
    return ok(res, { model: m });
  } catch (e) {
    next(e);
  }
});
app.patch("/api/v1/models/:modelId/status", auth, async (req, res, next) => {
  try {
    const m = await getModel(req, res);
    if (!m) return;
    if (typeof req.body.isActive !== "boolean")
      return error(res, 400, "VALIDATION_ERROR", "isActive must be a boolean.");
    m.isActive = req.body.isActive;
    m.updatedAt = now();
    await models.updateOne({ id: m.id }, { $set: m });
    return ok(res, { model: m });
  } catch (e) {
    next(e);
  }
});
app.delete("/api/v1/models/:modelId", auth, async (req, res, next) => {
  try {
    const m = await getModel(req, res);
    if (!m) return;
    await models.deleteOne({ id: m.id });
    return ok(res, { deleted: true });
  } catch (e) {
    next(e);
  }
});

async function rankWithGroq(prompt, candidates, assessment, context) {
  if (!process.env.GROQ_API_KEY || candidates.length < 2) return null;
  const response = await fetch("https://api.groq.com/openai/v1/chat/completions", { method: "POST", headers: { Authorization: `Bearer ${process.env.GROQ_API_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify({ model: process.env.GROQ_MODEL || "llama-3.3-70b-versatile", temperature: 0, response_format: { type: "json_object" }, messages: [{ role: "system", content: "Rank only the supplied AI models. First prioritize token/context size and choose the cheapest capable model. Use complexity signals only to upgrade when needed. Never choose an expensive model for a short simple prompt. Return JSON only: {recommendedModel, suitableModels, confidence, reason}. suitableModels must contain the supplied model IDs or exact names that can reasonably handle the prompt, including the recommended model. confidence must be 0-1." }, { role: "user", content: JSON.stringify({ prompt, candidates: candidates.map(({ id, displayName, providerName }) => ({ id, displayName, providerName })), assessment, context }) }] }) });
  if (!response.ok) return null;
  const data = await response.json();
  const ranking = JSON.parse(data.choices?.[0]?.message?.content || "{}");
  const recommended = candidates.find((model) => model.id === ranking.recommendedModel || model.displayName.toLowerCase() === String(ranking.recommendedModel).toLowerCase());
  if (!recommended) return null;
  const suitable = Array.isArray(ranking.suitableModels) ? ranking.suitableModels : [];
  return { recommended, suitable, confidence: Math.min(1, Math.max(0, Number(ranking.confidence) || 0.7)), reason: ranking.reason || "Groq balanced capability, context fit, and cost-efficiency." };
}

import { assess, choose, estimateTokens, fitsAssessment, maxPrompt, rankModels } from "./lib/recommendations.js";

const visibleRec = (r) => {
  const { userId, ...safe } = r;
  return safe;
};
const usageState = (items) => {
  const windowMs = 7 * 24 * 60 * 60 * 1000;
  let startedAt = null, count = 0;
  for (const item of items.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))) {
    const createdAt = new Date(item.createdAt);
    if (!startedAt || createdAt - startedAt >= windowMs || count >= 100) {
      startedAt = createdAt;
      count = 0;
    }
    count += 1;
  }
  return { count, startedAt, resetAt: startedAt ? new Date(startedAt.getTime() + windowMs) : null };
};
app.post("/api/v1/recommendations", auth, async (req, res, next) => {
  try {
    const prompt = String(req.body.prompt || "").trim();
    if (prompt.length < 3 || prompt.length > maxPrompt)
      return error(
        res,
        400,
        "VALIDATION_ERROR",
        `Prompt must be 3–${maxPrompt} characters.`
      );
    const ids = Array.isArray(req.body.candidateModelIds)
      ? [...new Set(req.body.candidateModelIds)]
      : [];
    const candidates = (await userModels(req.user.id)).filter(
      (m) => ids.includes(m.id) && m.isActive
    );
    if (!candidates.length)
      return error(
        res,
        400,
        "NO_ACTIVE_MODELS",
        "Select at least one active model."
      );
    const context = {
      hasContext: Boolean(req.body.context?.hasContext),
      contextType: req.body.context?.contextType || "none",
      contextDetails: String(req.body.context?.contextDetails || "").slice(0, 300),
      ...req.body.context,
    };
    const assessment = assess(prompt, context),
      fitCandidates = candidates.filter((model) => fitsAssessment(model, assessment)),
      ranked = rankModels(candidates, assessment),
      pricedCandidates = (fitCandidates.length ? fitCandidates : ranked).filter((model) => model.inputPricePerMillion != null),
      recommended = pricedCandidates[0] || choose(candidates, assessment),
      alternative = pricedCandidates.find((model) => model.id !== recommended.id) || ranked.find((model) => model.id !== recommended.id) || null,
      redacted = sanitize(prompt),
      confidence = candidates.length === 1 ? 0.72 : 0.6,
      inputTokens = estimateTokens(prompt),
      candidateCosts = candidates.map((model) => ({ model: model.displayName, usd: model.inputPricePerMillion == null ? null : inputTokens * model.inputPricePerMillion / 1000000 })),
      recommendedCost = candidateCosts.find((item) => item.model === recommended.displayName)?.usd,
      alternativeCost = alternative && candidateCosts.find((item) => item.model === alternative.displayName)?.usd,
      estimatedSavingsUsd = recommendedCost == null || alternativeCost == null ? null : Math.max(0, alternativeCost - recommendedCost),
      reasons = [
        `${assessment.taskType.replaceAll("_", " ")} needs ${assessment.reasoningRequirement}-level reasoning.`,
        "Fallback ranking balanced model capability and cost-efficiency.",
        context.hasContext
          ? "The supplied context metadata was included in the assessment."
          : "No additional context was reported.",
      ],
      summary = `${recommended.displayName} is the best fit among the selected models.`;
    const rec = await recommendations.create({
      id: id(),
      userId: req.user.id,
      genericPrompt: redacted.slice(0, 240),
      promptHash: promptHash(redacted),
      promptCharacterCount: prompt.length,
      candidateModels: candidates.map((m) => ({
        modelId: m.id,
        displayName: m.displayName,
      })),
      currentModel: null,
      context,
      contextDetails: context.contextDetails,
      assessment,
        result: {
        recommendedModelId: recommended.id,
        recommendedModelName: recommended.displayName,
        alternativeModelId: alternative?.id || null,
        alternativeModelName: alternative?.displayName || null,
        confidence,
        estimatedInputTokens: inputTokens,
        estimatedInputCostUsd: recommendedCost ?? null,
        estimatedSavingsUsd,
        reasons,
        summary,
      },
      feedback: null,
      createdAt: now(),
    });
    return ok(
      res,
      {
        recommendationId: rec.id,
        genericPrompt: rec.genericPrompt,
        recommendedModel: { id: recommended.id, name: recommended.displayName },
        alternativeModel: alternative
          ? { id: alternative.id, name: alternative.displayName }
          : null,
        assessment,
        contextDetails: context.contextDetails,
        confidence,
        estimatedInputTokens: inputTokens,
        estimatedInputCostUsd: recommendedCost ?? null,
        estimatedSavingsUsd,
        reasons,
        summary,
      },
      201
    );
  } catch (e) {
    next(e);
  }
});
app.get("/api/v1/recommendations", auth, async (req, res, next) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1),
      limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20)),
      all = await recommendations.find({ userId: req.user.id });
    return ok(res, {
      items: all.slice((page - 1) * limit, page * limit).map(visibleRec),
      pagination: {
        page,
        limit,
        total: all.length,
        totalPages: Math.ceil(all.length / limit),
      },
    });
  } catch (e) {
    next(e);
  }
});
app.get("/api/v1/usage", auth, async (req, res, next) => {
  try {
    const usage = usageState(await recommendations.find({ userId: req.user.id }));
    const expired = !usage.startedAt || Date.now() >= usage.resetAt || usage.count >= 100;
    return ok(res, { count: expired ? 0 : usage.count, limit: 100, resetAt: (expired ? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) : usage.resetAt).toISOString() });
  } catch (e) {
    next(e);
  }
});
app.get(
  "/api/v1/recommendations/:recommendationId",
  auth,
  async (req, res, next) => {
    try {
      const r = await recommendations.findOne({
        id: req.params.recommendationId,
        userId: req.user.id,
      });
      if (!r)
        return error(
          res,
          404,
          "RECOMMENDATION_NOT_FOUND",
          "Recommendation not found."
        );
      return ok(res, { recommendation: visibleRec(r) });
    } catch (e) {
      next(e);
    }
  }
);
app.patch("/api/v1/recommendations/:recommendationId/feedback", auth, async (req, res, next) => {
  try {
    const r = await recommendations.findOne({ id: req.params.recommendationId, userId: req.user.id });
    if (!r) return error(res, 404, "RECOMMENDATION_NOT_FOUND", "Recommendation not found.");
    r.feedback = { accepted: Boolean(req.body.accepted), selectedModelId: req.body.selectedModelId || null, rating: req.body.rating ?? null, createdAt: now() };
    r.updatedAt = now();
    await recommendations.updateOne({ id: r.id }, { $set: { feedback: r.feedback, updatedAt: r.updatedAt } });
    return ok(res, { recommendation: visibleRec(r) });
  } catch (e) {
    next(e);
  }
});
app.delete(
  "/api/v1/recommendations/:recommendationId",
  auth,
  async (req, res, next) => {
    try {
      const n = await recommendations.deleteOne({
        id: req.params.recommendationId,
        userId: req.user.id,
      });
      if (!n)
        return error(
          res,
          404,
          "RECOMMENDATION_NOT_FOUND",
          "Recommendation not found."
        );
      return ok(res, { deleted: true });
    } catch (e) {
      next(e);
    }
  }
);
app.delete("/api/v1/recommendations", auth, async (req, res, next) => {
  try {
    return ok(res, {
      deleted: await recommendations.deleteMany({ userId: req.user.id }),
    });
  } catch (e) {
    next(e);
  }
});
app.use((_req, res) => error(res, 404, "NOT_FOUND", "Route not found."));
app.use((err, _req, res, _next) => {
  console.error(err);
  if (err?.code === 11000) {
    return error(res, 409, "DUPLICATE_RECORD", "This record already exists.");
  }
  return error(res, 500, "INTERNAL_SERVER_ERROR", "Something went wrong.");
});
if (
  process.argv[1] &&
  decodeURIComponent(new URL(import.meta.url).pathname) === process.argv[1]
) {
  try {
    const result = await connectMongo({ mongoose });
    if (result.driver !== "mongo") {
      throw new Error(result.reason || "MongoDB is not configured.");
    }
    setPersistence(true);
    await removeLegacyIdIndexes();
    console.log(`MongoDB connected: ${process.env.MONGODB_DB_NAME || "ai_model_recommender"}`);
    app.listen(port, () =>
      console.log(
        `AI model recommender API listening on http://localhost:${port}`
      )
    );
  } catch (e) {
    console.error(`MongoDB connection failed: ${e.message}`);
    console.error("Backend was not started because MongoDB is required.");
    process.exitCode = 1;
  }
}
export { app, memory as db };
