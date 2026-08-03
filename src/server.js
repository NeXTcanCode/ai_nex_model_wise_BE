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
  memory,
  setPersistence,
  id,
} from "./persistence.js";
import {
  assess,
  choose,
  estimateTokens,
  fitsAssessment,
  maxPrompt,
  now,
  promptHash,
  rankModels,
  sanitize,
  userModels,
} from "./lib/recommendations.js";

const app = express();
const port = Number(process.env.PORT || 5001);
const cookieName = "mw_token";
const jwtSecret = process.env.JWT_SECRET || "change-me";
const jwtExpiresIn = process.env.JWT_EXPIRES_IN || "7d";
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
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email });

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
      password: passwordHash,
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
    const okPass = await bcrypt.compare(password, user.password || "");
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
      inputPricePerMillion:
        req.body.inputPricePerMillion == null
          ? null
          : Number(req.body.inputPricePerMillion),
      outputPricePerMillion:
        req.body.outputPricePerMillion == null
          ? null
          : Number(req.body.outputPricePerMillion),
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
      }));
    return ok(res, { suggestions });
  } catch (error) {
    next(error);
  }
});

const visibleRec = (r) => {
  const { userId, ...safe } = r;
  return safe;
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
      contextDetails: String(req.body.context?.contextDetails || "").slice(
        0,
        300
      ),
      ...req.body.context,
    };
    const assessment = assess(prompt, context),
      fitCandidates = candidates.filter((model) =>
        fitsAssessment(model, assessment)
      ),
      ranked = rankModels(candidates, assessment),
      pricedCandidates = (fitCandidates.length ? fitCandidates : ranked).filter(
        (model) => model.inputPricePerMillion != null
      ),
      recommended = pricedCandidates[0] || choose(candidates, assessment),
      alternative =
        pricedCandidates.find((model) => model.id !== recommended.id) ||
        ranked.find((model) => model.id !== recommended.id) ||
        null,
      redacted = sanitize(prompt),
      confidence = candidates.length === 1 ? 0.72 : 0.6,
      inputTokens = estimateTokens(prompt),
      recommendedCost =
        candidates.find((m) => m.displayName === recommended.displayName)
          ?.inputPricePerMillion == null
          ? null
          : (inputTokens *
              candidates.find((m) => m.displayName === recommended.displayName)
                .inputPricePerMillion) /
            1000000,
      alternativeCost =
        alternative?.inputPricePerMillion == null
          ? null
          : (inputTokens * alternative.inputPricePerMillion) / 1000000,
      estimatedSavingsUsd =
        recommendedCost == null || alternativeCost == null
          ? null
          : Math.max(0, alternativeCost - recommendedCost),
      reasons = [
        `${assessment.taskType.replaceAll("_", " ")} needs ${
          assessment.reasoningRequirement
        }-level reasoning.`,
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
    return ok(res, { count: 0, limit: 100, resetAt: now() });
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
