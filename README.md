# AI Model Recommender Backend

Express + MongoDB backend for AI model recommender app.

## What it does

- Register/login/logout users
- Keep auth in temporary sessions
- Save user-specific model list
- Add, edit, enable, disable, delete models
- Get model-name suggestions from OpenRouter
- Run model recommendation from prompt + context
- Rank models with local rules and Groq fallback
- Store recommendation history in MongoDB
- Redact common secrets from prompts before storage
- Track usage and feedback

## Tech

- Node.js
- Express
- MongoDB + Mongoose
- CORS
- Helmet
- dotenv
- Groq API
- OpenRouter API

## Run locally

```bash
npm install
npm run dev
```

## Start

```bash
npm start
```

## Env vars

```env
PORT=5001
MONGODB_URI=mongodb://127.0.0.1:27017/ai_model_recommender
MONGODB_DB_NAME=ai_model_recommender
FRONTEND_ORIGIN=http://localhost:5173
GROQ_API_KEY=your_key
GROQ_MODEL=llama-3.3-70b-versatile
OPENROUTER_API_KEY=your_key
MAX_PROMPT_CHARACTERS=20000
```

## API

Base path: `/api/v1`

### Auth

- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`
- `POST /auth/logout`

### Models

- `GET /models`
- `POST /models`
- `PATCH /models/:modelId`
- `PATCH /models/:modelId/status`
- `DELETE /models/:modelId`
- `POST /models/suggestions`
- `POST /models/pricing`

### Recommendations

- `POST /recommendations`
- `GET /recommendations`
- `GET /recommendations/:recommendationId`
- `PATCH /recommendations/:recommendationId/feedback`
- `DELETE /recommendations/:recommendationId`
- `DELETE /recommendations`

### Usage

- `GET /usage`

### Health

- `GET /health`

## Data flow

1. Frontend sends prompt + selected model ids + context.
2. Backend sanitizes prompt and hashes it.
3. Backend scores models locally.
4. Groq can rank as fallback/explanation path.
5. Backend stores generic prompt + metadata + result.

## Storage

Saved in MongoDB:

- user
- user models
- recommendation history
- feedback
- prompt hash
- generic prompt summary

Raw prompt is not stored by default.

## Deploy on Render

- Push backend folder to GitHub repo
- Create Render Web Service from repo
- Build: `npm install`
- Start: `npm start`
- Set env vars in Render
- Point frontend API base URL to Render URL

## Notes

- Frontend should use Render backend URL, not localhost
- Backend needs `FRONTEND_ORIGIN` set for CORS
- Local temp sessions are in-memory; restart clears them
