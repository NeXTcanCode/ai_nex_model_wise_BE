const { getEnv } = require('../config/env');
const { createMemoryStore } = require('./memory-store');

function createPersistence({ env = getEnv(), models = {}, memoryStore = createMemoryStore() } = {}) {
  if (env.persistenceDriver === 'memory' || !env.mongoUri || !models.Recommendation) {
    return { driver: 'memory', users: memoryStore, models: memoryStore, recommendations: memoryStore };
  }
  return {
    driver: 'mongo',
    users: { insert: value => models.User.create(value), list: (filter = {}) => models.User.find(filter).lean() },
    models: { insert: value => models.UserModel.create(value), list: (filter = {}) => models.UserModel.find(filter).lean() },
    recommendations: { insert: value => models.Recommendation.create(value), list: (filter = {}) => models.Recommendation.find(filter).sort({ createdAt: -1 }).lean() }
  };
}

module.exports = { createPersistence };
