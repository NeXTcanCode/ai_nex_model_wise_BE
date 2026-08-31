const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  id: { type: String, required: true },
  role: { type: String, enum: ['user', 'assistant'], required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, required: true },
  usage: { type: mongoose.Schema.Types.Mixed, default: null },
}, { _id: false, strict: 'throw' });

const schema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  title: { type: String, required: true, maxlength: 120 },
  messages: { type: [messageSchema], default: [] },
  preview: { type: String, default: '' },
}, { timestamps: true, versionKey: false, strict: 'throw' });

module.exports = mongoose.models.Conversation || mongoose.model('Conversation', schema);
