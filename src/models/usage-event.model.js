const mongoose = require("mongoose");

const schema = new mongoose.Schema(
  {
    userId: { type: String, required: true, index: true },
    inputTokens: { type: Number, required: true, min: 0 },
    outputTokens: { type: Number, required: true, min: 0 },
    cacheTokens: { type: Number, default: null, min: 0 },
    weightedUnits: { type: Number, required: true, min: 0 },
    provider: { type: String, enum: ["openrouter", "groq", "unknown"], default: "unknown" },
    responseMode: { type: String, enum: ["concise", "standard", "detailed"], required: true },
    providerReported: { type: Boolean, default: false },
  },
  { timestamps: true, versionKey: false, strict: "throw" }
);

module.exports = mongoose.models.UsageEvent || mongoose.model("UsageEvent", schema);
