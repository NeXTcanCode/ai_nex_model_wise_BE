const { getEnv } = require('./env');

async function connectMongo({ mongoose, env = getEnv() } = {}) {
  if (!mongoose) mongoose = require('mongoose');
  if (!env.mongoUri) return { driver: 'memory', reason: 'MONGODB_URI is not configured' };
  await mongoose.connect(env.mongoUri, { dbName: env.mongoDbName, serverSelectionTimeoutMS: 3000 });
  return { driver: 'mongo', connection: mongoose.connection };
}

async function disconnectMongo(mongoose = require('mongoose')) {
  if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
}

module.exports = { connectMongo, disconnectMongo };
