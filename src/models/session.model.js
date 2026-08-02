const mongoose = require('mongoose');
const schema = new mongoose.Schema({
  token: { type: String, required: true, unique: true, index: true },
  userId: { type: String, required: true, index: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } },
}, { versionKey: false });
module.exports = mongoose.models.Session || mongoose.model('Session', schema);
