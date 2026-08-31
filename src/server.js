import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";
import mongoose from "mongoose";
import { connectMongo } from "./config/database.js";
import {
  users,
  models,
  recommendations,
  usageEvents,
  conversations,
  skills,
  memory,
  setPersistence,
  id,
} from "./persistence.js";
import {
  assess,
  maxPrompt,
  now,
  promptHash,
  rankModels,
  recommendationConfidence,
  sanitize,
} from "./lib/recommendations.js";
import {
  USAGE_LIMITS,
  estimateTokens,
  outputMode,
  quotaError,
  usageSummary,
  weightedUnits,
} from "./lib/usage/quota.js";
import { buildConversationContext } from "./lib/chat/conversation.js";
import {
  isSafetyClassificationOnly,
  NEXT_AI_RESPONSE_FALLBACK,
  NEXT_AI_RETRY_INSTRUCTION,
} from "./lib/chat/response-validation.js";
import {
  analyzeImage,
  discardUploadedImage,
  ImageChatError,
  imageUpload,
} from "./lib/chat/image-chat.js";

const app = express();
const port = Number(process.env.PORT || 5001);
const cookieName = "mw_token";
const jwtSecret = process.env.JWT_SECRET || "change-me";
const jwtExpiresIn = process.env.JWT_EXPIRES_IN || "7d";
const nextAiUnavailableMessage =
  "NeXT AI is temporarily unavailable. Please try again in a moment.";
// IMAGE CHAT TEMPORARILY DISABLED.
// Change this to true to restore POST /api/v1/chat/image.
const imageChatEnabled = false;
const allowedOrigins = [
  "https://model-wise.netlify.app",
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  ...(process.env.FRONTEND_ORIGIN || "")
    .split(",")
    .map((origin) => origin.trim().replace(/\/$/, ""))
    .filter(Boolean),
];
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin.replace(/\/$/, ""))) {
      return callback(null, true);
    }
    return callback(new Error("CORS origin not allowed"));
  },
  credentials: true,
  methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 200,
};

app.use(helmet());
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

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
const optionalPrice = (value) => {
  if (value === null || value === undefined || value === "") return null;
  const price = Number(value);
  return Number.isFinite(price) && price >= 0 ? price : Number.NaN;
};
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email });
const userModels = (userId) => models.find({ userId });
const chatTitle = (prompt) => {
  const value = String(prompt || '').trim().replace(/\s+/g, ' ');
  return value.length > 60 ? `${value.slice(0, 57)}…` : value || 'New chat';
};
const skillSlug = (name) => normalize(name).replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || `skill-${id().slice(0, 8)}`;

const signToken = (user) =>
  jwt.sign({ sub: user.id }, jwtSecret, { expiresIn: jwtExpiresIn });
const setAuthCookie = (res, token) =>
  res.cookie(cookieName, token, {
    httpOnly: true,
    sameSite: "none",
    secure: true,
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
const clearAuthCookie = (res) =>
  res.clearCookie(cookieName, {
    httpOnly: true,
    sameSite: "none",
    secure: true,
  });

async function auth(req, res, next) {
  const token =
    req.cookies?.[cookieName] ||
    req.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return error(res, 401, "UNAUTHORIZED", "Login required.");
  try {
    const payload = jwt.verify(token, jwtSecret);
    const user = await users.findOne({ id: payload.sub });
    if (!user) return error(res, 401, "UNAUTHORIZED", "Login required.");
    req.user = user;
    next();
  } catch {
    return error(res, 401, "UNAUTHORIZED", "Login required.");
  }
}

const authPayload = (user, token) => ({
  user: publicUser(user),
  token,
  authMode: "jwt",
});

app.get("/health", (_req, res) =>
  ok(res, {
    status: "ok",
    service: "ai-model-recommender-api",
    authMode: "jwt",
    persistence: mongoose.connection.readyState === 1 ? "mongodb" : "memory",
  })
);

app.post("/api/v1/auth/register", async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = normalize(req.body.email);
    const password = String(req.body.password || "");
    if (!name || !email || !password)
      return error(
        res,
        400,
        "VALIDATION_ERROR",
        "Name, email, password required."
      );
    if (password.length < 8)
      return error(
        res,
        400,
        "VALIDATION_ERROR",
        "Password must be at least 8 characters."
      );
    if (await users.findOne({ email }))
      return error(
        res,
        409,
        "USER_ALREADY_EXISTS",
        "An account with that email already exists."
      );
    const passwordHash = await bcrypt.hash(
      password,
      Number(process.env.BCRYPT_SALT_ROUNDS || 12)
    );
    const user = await users.create({
      id: id(),
      name,
      email,
      passwordHash,
      createdAt: now(),
    });
    const token = signToken(user);
    setAuthCookie(res, token);
    return ok(res, authPayload(user, token), 201);
  } catch (e) {
    next(e);
  }
});

app.post("/api/v1/auth/login", async (req, res, next) => {
  try {
    const email = normalize(req.body.email);
    const password = String(req.body.password || "");
    const user = await users.findOne({ email });
    if (!user)
      return error(
        res,
        401,
        "INVALID_CREDENTIALS",
        "Email or password is incorrect."
      );
    const okPass = await bcrypt.compare(password, user.passwordHash || "");
    if (!okPass)
      return error(
        res,
        401,
        "INVALID_CREDENTIALS",
        "Email or password is incorrect."
      );
    const token = signToken(user);
    setAuthCookie(res, token);
    return ok(res, authPayload(user, token));
  } catch (e) {
    next(e);
  }
});

app.get("/api/v1/auth/me", auth, (req, res) =>
  ok(res, { user: publicUser(req.user), authMode: "jwt" })
);

app.post("/api/v1/auth/logout", async (req, res, next) => {
  try {
    clearAuthCookie(res);
    return ok(res, { loggedOut: true });
  } catch (e) {
    next(e);
  }
});

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
    const inputPricePerMillion = optionalPrice(req.body.inputPricePerMillion);
    const outputPricePerMillion = optionalPrice(req.body.outputPricePerMillion);
    if (!displayName)
      return error(res, 400, "VALIDATION_ERROR", "Model name is required.");
    if (Number.isNaN(inputPricePerMillion) || Number.isNaN(outputPricePerMillion))
      return error(
        res,
        400,
        "VALIDATION_ERROR",
        "Model prices must be non-negative numbers."
      );
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
      openRouterModelId: req.body.openRouterModelId || null,
      inputPricePerMillion,
      outputPricePerMillion,
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
    const q = normalize(req.body.query),
      words = q.split(/\s+/).filter(Boolean),
      headers = {};
    if (
      process.env.OPENROUTER_API_KEY &&
      !process.env.OPENROUTER_API_KEY.startsWith("replace-")
    )
      headers.Authorization = `Bearer ${process.env.OPENROUTER_API_KEY}`;
    const response = await fetch("https://openrouter.ai/api/v1/models", {
      headers,
    });
    if (!response.ok)
      return error(
        res,
        502,
        "SUGGESTIONS_LOOKUP_FAILED",
        `OpenRouter returned ${response.status}.`
      );
    const data = await response.json();
    const suggestions = (data.data || [])
      .filter((model) => {
        const text = normalize(
          `${model.name} ${model.id} ${model.description || ""}`
        );
        return !words.length || words.every((word) => text.includes(word));
      })
      .slice(0, 5)
      .map((model) => ({
        displayName: model.name,
      providerName: model.id.split("/")[0] || "Unknown",
      openRouterModelId: model.id,
    }));
    return ok(res, { suggestions });
  } catch (error) {
    next(error);
  }
});
app.get("/api/v1/models/catalog", auth, async (req, res, next) => {
  try {
    const headers = {};
    if (process.env.OPENROUTER_API_KEY && !process.env.OPENROUTER_API_KEY.startsWith("replace-")) {
      headers.Authorization = `Bearer ${process.env.OPENROUTER_API_KEY}`;
    }
    const response = await fetch("https://openrouter.ai/api/v1/models", { headers });
    if (!response.ok)
      return error(res, 502, "CATALOG_LOOKUP_FAILED", `OpenRouter returned ${response.status}.`);
    const data = await response.json();
    const models = (data.data || []).map((model) => ({
      displayName: model.name || model.id,
      providerName: model.id?.split("/")[0] || "Other",
      openRouterModelId: model.id,
      inputPricePerMillion: model.pricing?.prompt == null ? null : Number(model.pricing.prompt) * 1000000,
      outputPricePerMillion: model.pricing?.completion == null ? null : Number(model.pricing.completion) * 1000000,
    }));
    return ok(res, { models });
  } catch (e) {
    next(e);
  }
});
app.post("/api/v1/models/pricing", auth, async (req, res, next) => {
  try {
    const query = normalize(req.body.query);
    const words = query.split(/\s+/).filter(Boolean);
    const headers = {};
    if (process.env.OPENROUTER_API_KEY && !process.env.OPENROUTER_API_KEY.startsWith("replace-")) {
      headers.Authorization = `Bearer ${process.env.OPENROUTER_API_KEY}`;
    }
    const response = await fetch("https://openrouter.ai/api/v1/models", { headers });
    if (!response.ok) {
      return error(res, 502, "PRICING_LOOKUP_FAILED", `OpenRouter returned ${response.status}.`);
    }
    const data = await response.json();
    const match = (data.data || []).find((model) => {
      const text = normalize(`${model.name} ${model.id}`);
      return words.every((word) => text.includes(word));
    });
    return ok(res, {
      pricing: match?.pricing
        ? {
            inputPricePerMillion: Number(match.pricing.prompt) * 1000000,
            outputPricePerMillion: Number(match.pricing.completion) * 1000000,
            currency: "USD",
            source: "OpenRouter",
            modelId: match.id,
          }
        : null,
    });
  } catch (error) {
    next(error);
  }
});

const visibleRec = (r) => {
  const { userId, ...safe } = r;
  return safe;
};

app.post('/api/v1/chats', auth, async (req, res, next) => {
  try {
    const chat = await conversations.create({ id: id(), userId: req.user.id, title: chatTitle(req.body.title), messages: [], preview: '', createdAt: now(), updatedAt: now() });
    return ok(res, { chat }, 201);
  } catch (e) { next(e); }
});
app.get('/api/v1/chats', auth, async (req, res, next) => {
  try {
    const chats = (await conversations.find({ userId: req.user.id })).sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt)).map(({ messages, ...chat }) => ({ ...chat, messageCount: messages?.length || 0 }));
    return ok(res, { chats });
  } catch (e) { next(e); }
});
app.get('/api/v1/chats/:chatId', auth, async (req, res, next) => {
  try {
    const chat = await conversations.findOne({ id: req.params.chatId, userId: req.user.id });
    if (!chat) return error(res, 404, 'CHAT_NOT_FOUND', 'Chat not found.');
    return ok(res, { chat });
  } catch (e) { next(e); }
});
app.patch('/api/v1/chats/:chatId', auth, async (req, res, next) => {
  try {
    const chat = await conversations.findOne({ id: req.params.chatId, userId: req.user.id });
    if (!chat) return error(res, 404, 'CHAT_NOT_FOUND', 'Chat not found.');
    const title = String(req.body.title || '').trim();
    if (!title) return error(res, 400, 'VALIDATION_ERROR', 'Chat title is required.');
    chat.title = title.slice(0, 120); chat.updatedAt = now();
    await conversations.updateOne({ id: chat.id, userId: req.user.id }, { $set: { title: chat.title, updatedAt: chat.updatedAt } });
    return ok(res, { chat });
  } catch (e) { next(e); }
});
app.delete('/api/v1/chats/:chatId', auth, async (req, res, next) => {
  try {
    const deleted = await conversations.deleteOne({ id: req.params.chatId, userId: req.user.id });
    if (!deleted) return error(res, 404, 'CHAT_NOT_FOUND', 'Chat not found.');
    return ok(res, { deleted: true });
  } catch (e) { next(e); }
});

app.get('/api/v1/skills', auth, async (req, res, next) => {
  try {
    const records = (await skills.find({ userId: req.user.id })).sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    return ok(res, { skills: records });
  } catch (e) { next(e); }
});
app.post('/api/v1/skills', auth, async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim();
    const markdown = String(req.body.markdown || '').trim();
    if (!name || !markdown) return error(res, 400, 'VALIDATION_ERROR', 'Skill name and Markdown are required.');
    const skill = await skills.create({ id: id(), userId: req.user.id, slug: skillSlug(name), name: name.slice(0, 80), description: String(req.body.description || '').slice(0, 240), markdown: markdown.slice(0, 20000), createdAt: now(), updatedAt: now() });
    return ok(res, { skill }, 201);
  } catch (e) { next(e); }
});
app.get('/api/v1/skills/:skillId', auth, async (req, res, next) => {
  try {
    const skill = await skills.findOne({ id: req.params.skillId, userId: req.user.id });
    if (!skill) return error(res, 404, 'SKILL_NOT_FOUND', 'Skill not found.');
    return ok(res, { skill });
  } catch (e) { next(e); }
});
app.patch('/api/v1/skills/:skillId', auth, async (req, res, next) => {
  try {
    const skill = await skills.findOne({ id: req.params.skillId, userId: req.user.id });
    if (!skill) return error(res, 404, 'SKILL_NOT_FOUND', 'Skill not found.');
    const values = {};
    if (req.body.name !== undefined) values.name = String(req.body.name).trim().slice(0, 80);
    if (req.body.description !== undefined) values.description = String(req.body.description).slice(0, 240);
    if (req.body.markdown !== undefined) values.markdown = String(req.body.markdown).trim().slice(0, 20000);
    if (!values.name && req.body.name !== undefined) return error(res, 400, 'VALIDATION_ERROR', 'Skill name is required.');
    if (!values.markdown && req.body.markdown !== undefined) return error(res, 400, 'VALIDATION_ERROR', 'Skill Markdown is required.');
    values.updatedAt = now();
    Object.assign(skill, values);
    await skills.updateOne({ id: skill.id, userId: req.user.id }, { $set: values });
    return ok(res, { skill });
  } catch (e) { next(e); }
});
app.delete('/api/v1/skills/:skillId', auth, async (req, res, next) => {
  try {
    const deleted = await skills.deleteOne({ id: req.params.skillId, userId: req.user.id });
    if (!deleted) return error(res, 404, 'SKILL_NOT_FOUND', 'Skill not found.');
    return ok(res, { deleted: true });
  } catch (e) { next(e); }
});

const applyNextAiIdentity = (value) => {
  const text = String(value || "").trim();
  if (!text) return text;

  const firstPersonModelIntroduction =
    /^(?:(?:i(?:'m|’m| am)|as)\b[^.!?]*(?:language model|\bmodel\b|\bai\b|assistant|developed|trained|created|built|powered)[^.!?]*[.!?]\s*)/i;

  return firstPersonModelIntroduction.test(text)
    ? text.replace(
        firstPersonModelIntroduction,
        "I'm NeXT AI, the intelligent assistant inside Modelwise. "
      )
    : text;
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
    const rawContext =
      req.body.context && typeof req.body.context === "object"
        ? req.body.context
        : {};
    const hasContext = Boolean(rawContext.hasContext);
    const context = {
      hasContext,
      contextType: hasContext
        ? String(rawContext.contextType || "other").slice(0, 40)
        : "none",
      contextDetails: hasContext
        ? sanitize(String(rawContext.contextDetails || "")).slice(0, 300)
        : "",
    };
    const assessment = assess(prompt, context),
      inputTokens = assessment.estimatedInputTokens,
      scoredRanking = rankModels(candidates, assessment, { inputTokens }),
      confidence = recommendationConfidence(scoredRanking, assessment),
      ranking = scoredRanking.map(({ profileCertainty, ...model }) => model),
      recommended = ranking[0],
      alternative = ranking[1] || null,
      redacted = sanitize(prompt),
      recommendedCost = recommended.estimatedInputCostUsd,
      alternativeCost = alternative?.estimatedInputCostUsd ?? null,
      estimatedSavingsUsd =
        recommendedCost == null || alternativeCost == null
          ? null
          : Math.max(0, alternativeCost - recommendedCost),
      reasons = recommended.reasons,
      summary = `${recommended.displayName} ranked first with a ${recommended.score}/100 fit score for this ${assessment.taskType} task.`;
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
        ranking,
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
        ranking,
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
      all = (await recommendations.find({ userId: req.user.id })).sort(
        (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
      );
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
    return ok(res, usageSummary(await usageEvents.find({ userId: req.user.id })));
  } catch (e) {
    next(e);
  }
});
app.get("/api/v1/usage/history", auth, async (req, res, next) => {
  try {
    const days = Math.min(30, Math.max(1, Number(req.query.days) || 7));
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const events = (await usageEvents.find({ userId: req.user.id })).filter((event) => new Date(event.createdAt).getTime() >= cutoff);
    return ok(res, { events });
  } catch (e) { next(e); }
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
app.patch(
  "/api/v1/recommendations/:recommendationId/feedback",
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
      r.feedback = {
        accepted: Boolean(req.body.accepted),
        selectedModelId: req.body.selectedModelId || null,
        rating: req.body.rating ?? null,
        createdAt: now(),
      };
      r.updatedAt = now();
      await recommendations.updateOne(
        { id: r.id },
        { $set: { feedback: r.feedback, updatedAt: r.updatedAt } }
      );
      return ok(res, { recommendation: visibleRec(r) });
    } catch (e) {
      next(e);
    }
  }
);
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
app.post(["/api/v1/chat", "/api/v1/chatRequest"], auth, async (req, res, next) => {
  try {
    const prompt = String(req.body.prompt || "").trim();
    if (prompt.length < 1 || prompt.length > maxPrompt)
      return error(res, 400, "VALIDATION_ERROR", `Prompt must be 1–${maxPrompt} characters.`);

    const conversationId = String(req.body.conversationId || '').trim() || null;
    const conversationRecord = conversationId
      ? await conversations.findOne({ id: conversationId, userId: req.user.id })
      : null;
    if (conversationId && !conversationRecord)
      return error(res, 404, 'CHAT_NOT_FOUND', 'Chat not found.');

    const identityQuestion = /\b(who are you|what (?:ai|model) are you|which (?:ai |language )?model|what is your (?:name|model)|your model name|what powers you)\b/i;
    if (identityQuestion.test(prompt)) {
      return ok(res, {
        response:
          "I'm NeXT AI, the AI assistant created by Vikas Sinha under the NeXT brand and available through Modelwise. I can help with questions, analysis, coding, writing, and creative tasks. What can I help you with today?",
        provider: "NeXT AI",
        model: "next-ai",
        usage: null,
      });
    }

    const selectedOutputMode = outputMode(req.body.responseMode);
    const modeConfig = USAGE_LIMITS.outputModes[selectedOutputMode];
    const answerStyle = ["standard", "structured", "code-only"].includes(req.body.answerStyle)
      ? req.body.answerStyle
      : "standard";
    const answerStyleInstruction = {
      standard: "",
      structured: "Use clear sections such as Summary, Details, and Next steps when helpful.",
      "code-only": "For coding requests, return only the necessary code and minimal inline comments.",
    }[answerStyle];
    const coderTask = ["debug", "build", "review", "refactor", "test"].includes(req.body.coderTask)
      ? req.body.coderTask
      : null;
    const coderTaskInstruction = {
      debug: "Focus on diagnosis, root cause, a concrete fix, and verification steps.",
      build: "Focus on an implementation plan, affected components, working code, and verification.",
      review: "Review for correctness, security, performance, and maintainability; prioritize actionable findings.",
      refactor: "Improve structure and maintainability while preserving behavior; explain important trade-offs.",
      test: "Focus on unit, integration, and edge-case tests, including how to run and verify them.",
    }[coderTask] || "";
    const conversation = buildConversationContext(req.body.messages, prompt);
    const estimatedInputTokens = conversation.estimatedInputTokens;

    // QUOTA ENFORCEMENT TEMPORARILY DISABLED
    // Keep usage calculation and UsageEvent persistence active so limits can be
    // restored later with real usage data. Uncomment this block to re-enable
    // the rules configured in src/lib/usage/quota.js.
    // const currentUsage = usageSummary(
    //   await usageEvents.find({ userId: req.user.id })
    // );
    // const limitMessage = quotaError({
    //   summary: currentUsage,
    //   estimatedInputTokens,
    // });
    // if (limitMessage) {
    //   return error(res, 429, "USAGE_LIMIT_REACHED", limitMessage, [
    //     { usage: currentUsage },
    //   ]);
    // }

    if (!process.env.OPENROUTER_API_KEY || process.env.OPENROUTER_API_KEY.startsWith("replace-"))
      return error(res, 503, "AI_PROVIDER_NOT_CONFIGURED", "OpenRouter is not configured.");

    const requestOpenRouter = async (isRetry = false) => {
      const providerResponse = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": process.env.FRONTEND_ORIGIN || "http://localhost:5173",
          "X-Title": "NeXT AI",
        },
        body: JSON.stringify({
          model: "openrouter/free",
          messages: [
            {
              role: "system",
              content:
                "You are NeXT AI, the assistant inside Modelwise. " +
                "NeXT AI is the AI assistant created by Vikas Sinha under the NeXT brand and available through Modelwise. " +
                "Identify yourself only as NeXT AI. " +
                "Do not speculate about or disclose an underlying provider or model. " +
                `If asked which model you are, reply that you are NeXT AI. ${answerStyleInstruction} ${coderTaskInstruction}`,
            },
            ...(isRetry
              ? [{ role: "system", content: NEXT_AI_RETRY_INSTRUCTION }]
              : []),
            ...conversation.messages,
          ],
          provider: { allow_fallbacks: false },
        }),
      });
      const providerData = await providerResponse.json().catch(() => ({}));
      return { providerResponse, providerData };
    };

    const retryTransientProviderFailure = async (result) => {
      const status = result.providerResponse.status;
      if (status !== 429 && status < 500) return result;

      const retryAfter = Number(
        result.providerResponse.headers.get("retry-after") || 0
      );
      const retryDelayMs = Number.isFinite(retryAfter)
        ? Math.min(2000, Math.max(0, retryAfter * 1000))
        : 0;
      if (retryDelayMs) {
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
      }
      return requestOpenRouter(true);
    };

    let providerResult = await requestOpenRouter();
    if (!providerResult.providerResponse.ok) {
      providerResult = await retryTransientProviderFailure(providerResult);
    }
    let { providerResponse, providerData: data } = providerResult;
    if (!providerResponse.ok) {
      console.error("OpenRouter chat request failed:", data.error || data);
      return error(
        res,
        503,
        "OPENROUTER_REQUEST_FAILED",
        nextAiUnavailableMessage
      );
    }

    let responseContent = data.choices?.[0]?.message?.content || "";
    if (isSafetyClassificationOnly(responseContent)) {
      ({ providerResponse, providerData: data } = await requestOpenRouter(true));
      if (!providerResponse.ok) {
        console.error("OpenRouter chat retry failed:", data.error || data);
        return error(
          res,
          503,
          "OPENROUTER_REQUEST_FAILED",
          nextAiUnavailableMessage
        );
      }
      responseContent = data.choices?.[0]?.message?.content || "";
    }

    const finalResponse = isSafetyClassificationOnly(responseContent)
      ? NEXT_AI_RESPONSE_FALLBACK
      : responseContent || NEXT_AI_RESPONSE_FALLBACK;

    const providerInputTokens = Number(data.usage?.prompt_tokens);
    const providerOutputTokens = Number(data.usage?.completion_tokens);
    const inputTokens = Number.isFinite(providerInputTokens)
      ? providerInputTokens
      : estimatedInputTokens;
    const outputTokens = Number.isFinite(providerOutputTokens)
      ? providerOutputTokens
      : estimateTokens(finalResponse);
    await usageEvents.create({
      userId: req.user.id,
      inputTokens,
      outputTokens,
      weightedUnits: weightedUnits(inputTokens, outputTokens),
      responseMode: selectedOutputMode,
      providerReported: Number.isFinite(providerInputTokens) && Number.isFinite(providerOutputTokens),
      createdAt: now(),
    });
    const updatedUsage = usageSummary(await usageEvents.find({ userId: req.user.id }));

    if (conversationRecord) {
      const timestamp = now();
      const nextTitle = conversationRecord.title === 'New chat'
        ? chatTitle(prompt)
        : conversationRecord.title;
      const persistedMessages = [
        ...(conversationRecord.messages || []),
        { id: id(), role: 'user', content: prompt, createdAt: timestamp, usage: null },
        { id: id(), role: 'assistant', content: finalResponse, createdAt: timestamp, usage: data.usage || null },
      ];
      await conversations.updateOne(
        { id: conversationRecord.id, userId: req.user.id },
        { $set: { title: nextTitle, messages: persistedMessages, preview: finalResponse.slice(0, 160), updatedAt: timestamp } }
      );
    }

    return ok(res, {
      response: applyNextAiIdentity(
        finalResponse
      ),
      provider: "OpenRouter Free Models Router",
      model: data.model || "openrouter/free",
      usage: data.usage || null,
      quota: updatedUsage,
    });
  } catch (e) {
    next(e);
  }
});

const uploadSingleChatImage = (req, res, next) => {
  imageUpload.single("image")(req, res, (uploadError) => {
    if (!uploadError) return next();
    if (uploadError.code === "LIMIT_FILE_SIZE") {
      return error(
        res,
        413,
        "IMAGE_TOO_LARGE",
        "Choose an image smaller than 5 MB."
      );
    }
    if (uploadError instanceof ImageChatError) {
      return error(
        res,
        uploadError.status,
        uploadError.code,
        uploadError.message
      );
    }
    return error(res, 400, "IMAGE_UPLOAD_FAILED", "Could not upload the image.");
  });
};

const requireImageChatEnabled = (_req, res, next) => {
  if (imageChatEnabled) return next();
  return error(
    res,
    404,
    "IMAGE_CHAT_DISABLED",
    "Image conversations are not currently available."
  );
};

app.post(
  "/api/v1/chat/image",
  auth,
  requireImageChatEnabled,
  uploadSingleChatImage,
  async (req, res, next) => {
    try {
      const prompt = String(req.body.prompt || "").trim() || "Describe this image.";
      if (prompt.length > maxPrompt) {
        discardUploadedImage(req.file);
        return error(
          res,
          400,
          "VALIDATION_ERROR",
          `Prompt must be no more than ${maxPrompt} characters.`
        );
      }
      if (!process.env.OPENROUTER_API_KEY || process.env.OPENROUTER_API_KEY.startsWith("replace-")) {
        discardUploadedImage(req.file);
        return error(
          res,
          503,
          "AI_PROVIDER_NOT_CONFIGURED",
          "OpenRouter is not configured."
        );
      }

      let incomingMessages = [];
      try {
        incomingMessages = JSON.parse(req.body.messages || "[]");
      } catch {
        discardUploadedImage(req.file);
        return error(res, 400, "VALIDATION_ERROR", "Conversation messages are invalid.");
      }

      const selectedOutputMode = outputMode(req.body.responseMode);
      const modeConfig = USAGE_LIMITS.outputModes[selectedOutputMode];
      const conversation = buildConversationContext(incomingMessages, prompt);
      const result = await analyzeImage({
        file: req.file,
        prompt,
        conversationMessages: conversation.messages,
        modeConfig,
        apiKey: process.env.OPENROUTER_API_KEY,
        referer: process.env.FRONTEND_ORIGIN || "http://localhost:5173",
      });

      const providerInputTokens = Number(result.usage?.prompt_tokens);
      const providerOutputTokens = Number(result.usage?.completion_tokens);
      const inputTokens = Number.isFinite(providerInputTokens)
        ? providerInputTokens
        : conversation.estimatedInputTokens;
      const outputTokens = Number.isFinite(providerOutputTokens)
        ? providerOutputTokens
        : estimateTokens(result.response);
      await usageEvents.create({
        userId: req.user.id,
        inputTokens,
        outputTokens,
        weightedUnits: weightedUnits(inputTokens, outputTokens),
        responseMode: selectedOutputMode,
        providerReported:
          Number.isFinite(providerInputTokens) &&
          Number.isFinite(providerOutputTokens),
        createdAt: now(),
      });
      const updatedUsage = usageSummary(
        await usageEvents.find({ userId: req.user.id })
      );

      return ok(res, {
        response: applyNextAiIdentity(result.response),
        provider: "NeXT AI Vision",
        model: result.model,
        usage: result.usage,
        quota: updatedUsage,
      });
    } catch (imageError) {
      if (imageError instanceof ImageChatError) {
        return error(
          res,
          imageError.status,
          imageError.code,
          imageError.message
        );
      }
      next(imageError);
    }
  }
);
app.use((_req, res) => error(res, 404, "NOT_FOUND", "Route not found."));
app.use((err, _req, res, _next) => {
  console.error(err);
  return error(res, 500, "INTERNAL_SERVER_ERROR", "Something went wrong.");
});

if (
  process.argv[1] &&
  decodeURIComponent(new URL(import.meta.url).pathname) === process.argv[1]
) {
  try {
    const result = await connectMongo({ mongoose });
    if (result.driver !== "mongo")
      throw new Error(result.reason || "MongoDB is not configured.");
    setPersistence(true);
    console.log(
      `MongoDB connected: ${
        process.env.MONGODB_DB_NAME || "ai_model_recommender"
      }`
    );
    app.listen(port, () =>
      console.log(
        `AI model recommender API listening on http://localhost:${port}`
      )
    );
  } catch (e) {
    console.error(`MongoDB connection failed: ${e.message}`);
    process.exitCode = 1;
  }
}

export { app, memory as db };
