const crypto = require('node:crypto');

function createMemoryStore() {
  const collections = { users: [], models: [], recommendations: [] };
  const id = () => crypto.randomUUID();
  return {
    async insert(collection, value) { const record = { _id: id(), ...value, createdAt: new Date(), updatedAt: new Date() }; collections[collection].push(record); return { ...record }; },
    async list(collection, predicate = () => true) { return collections[collection].filter(predicate).map(record => ({ ...record })); },
    async clear() { Object.values(collections).forEach(items => items.splice(0)); }
  };
}

module.exports = { createMemoryStore };
