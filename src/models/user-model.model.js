const mongoose = require('mongoose');
const schema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  displayName: { type: String, required: true }, normalizedName: { type: String, required: true }, providerName: String,
  openRouterModelId: { type: String, default: null },
  notes: { type: String, default: '' }, isActive: { type: Boolean, default: true }, source: String,
  inputPricePerMillion: { type: Number, min: 0, default: null }, outputPricePerMillion: { type: Number, min: 0, default: null }, pricingCurrency: { type: String, default: 'USD' },
}, { timestamps: true, versionKey: false, strict: 'throw' });
schema.index({ userId: 1, normalizedName: 1 }, { unique: true });
module.exports = mongoose.models.UserModel || mongoose.model('UserModel', schema);
