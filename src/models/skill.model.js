const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  slug: { type: String, required: true },
  name: { type: String, required: true, trim: true, maxlength: 80 },
  description: { type: String, default: '', maxlength: 240 },
  markdown: { type: String, required: true, maxlength: 20000 },
}, { timestamps: true, versionKey: false, strict: 'throw' });

schema.index({ userId: 1, slug: 1 }, { unique: true });
module.exports = mongoose.models.Skill || mongoose.model('Skill', schema);
