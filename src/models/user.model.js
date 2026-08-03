const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 120 },
  email: { type: String, required: true, trim: true, lowercase: true, unique: true, index: true },
  passwordHash: { type: String, required: true, select: true },
}, { timestamps: true, versionKey: false, strict: 'throw' });
module.exports = mongoose.models.User || mongoose.model('User', userSchema);
