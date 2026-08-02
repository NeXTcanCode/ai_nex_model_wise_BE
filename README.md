# AI Model Recommender API (initial phase)

Run `npm install` and `npm start` from this directory. The API is available at `http://localhost:5000`.

This initial checking build deliberately uses an in-memory data store and opaque temporary session tokens. It does **not** use JWT, bcrypt, MongoDB, or Groq yet. Restarting the server clears users, models, sessions, and history. Replace `src/server.js` storage/auth adapters with MongoDB and production authentication in the next phase.

Implemented routes follow the spec under `/api/v1`: auth, model CRUD/suggestions, recommendation creation, and paginated recommendation history/deletion. `GET /health` is available for smoke checks.
# ai_nex_model_wise_BE
