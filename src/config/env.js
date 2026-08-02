const getEnv = (env = process.env) => ({
  nodeEnv: env.NODE_ENV || 'development',
  mongoUri: env.MONGODB_URI || '',
  mongoDbName: env.MONGODB_DB_NAME || 'ai_model_recommender',
  persistenceDriver: env.PERSISTENCE_DRIVER || 'auto'
});

module.exports = { getEnv };
