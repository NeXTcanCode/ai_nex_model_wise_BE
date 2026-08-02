const mongoose = require('mongoose');
const schema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  genericPrompt: String, promptHash: { type: String, required: true }, promptCharacterCount: Number,
  candidateModels: { type: [mongoose.Schema.Types.Mixed], required: true }, currentModel: mongoose.Schema.Types.Mixed,
  context: mongoose.Schema.Types.Mixed, assessment: mongoose.Schema.Types.Mixed, result: mongoose.Schema.Types.Mixed,
  feedback: { type: mongoose.Schema.Types.Mixed, default: null },
  contextDetails: { type: String, default: "" },
}, { timestamps: true, versionKey: false, strict: 'throw' });
module.exports = mongoose.models.Recommendation || mongoose.model('Recommendation', schema);
