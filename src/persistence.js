import crypto from 'node:crypto';
import User from './models/user.model.js';
import UserModel from './models/user-model.model.js';
import Recommendation from './models/recommendation.model.js';
import UsageEvent from './models/usage-event.model.js';
import Conversation from './models/conversation.model.js';

export const memory = { users: [], models: [], recommendations: [], usageEvents: [], conversations: [] };
let mongo = false;
export const setPersistence = (value) => { mongo = value; };
const id = () => crypto.randomUUID();
const clean = (doc) => {
  const value = doc?.toObject ? doc.toObject() : doc;
  if (!value) return value;
  const { _id, ...rest } = value;
  return _id ? { ...rest, id: String(_id) } : rest;
};
const mongoFilter = (filter) => {
  const { id, ...rest } = filter;
  return id === undefined ? rest : { ...rest, _id: id };
};
const mongoValues = (value) => {
  const { id, _id, ...rest } = value;
  return rest;
};
const collection = (Model, key) => ({
  async findOne(filter) { return clean(mongo ? await Model.findOne(mongoFilter(filter)) : memory[key].find(x => Object.entries(filter).every(([k,v]) => x[k] === v))); },
  async find(filter = {}) { const rows = mongo ? await Model.find(mongoFilter(filter)).lean() : memory[key].filter(x => Object.entries(filter).every(([k,v]) => x[k] === v)); return rows.map(clean); },
  async create(value) { const row = { ...value }; if (mongo) return clean(await Model.create(mongoValues(row))); memory[key].push(row); return row; },
  async updateOne(filter, update) { const row = await this.findOne(filter); if (!row) return null; const values = update.$set || update; Object.assign(row, values); if (mongo) await Model.updateOne(mongoFilter(filter), { $set: mongoValues(values) }); return row; },
  async deleteOne(filter) { if (mongo) return (await Model.deleteOne(mongoFilter(filter))).deletedCount; const i = memory[key].findIndex(x => Object.entries(filter).every(([k,v]) => x[k] === v)); if (i >= 0) memory[key].splice(i, 1); return i >= 0 ? 1 : 0; },
  async deleteMany(filter) { if (mongo) return (await Model.deleteMany(mongoFilter(filter))).deletedCount; const before = memory[key].length; memory[key] = memory[key].filter(x => !Object.entries(filter).every(([k,v]) => x[k] === v)); return before - memory[key].length; },
});
export const users = collection(User, 'users');
export const models = collection(UserModel, 'models');
export const recommendations = collection(Recommendation, 'recommendations');
export const usageEvents = collection(UsageEvent, 'usageEvents');
export const conversations = collection(Conversation, 'conversations');
export { id };
