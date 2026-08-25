import multer from "multer";
import {
  isSafetyClassificationOnly,
  NEXT_AI_RESPONSE_FALLBACK,
  NEXT_AI_RETRY_INSTRUCTION,
} from "./response-validation.js";

export const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
export const VISION_MODEL =
  process.env.OPENROUTER_VISION_MODEL || "google/gemma-4-26b-a4b-it:free";

const ALLOWED_IMAGE_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
]);

export const imageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { files: 1, fileSize: MAX_IMAGE_BYTES },
  fileFilter: (_req, file, callback) => {
    if (!ALLOWED_IMAGE_TYPES.has(file.mimetype)) {
      return callback(
        new ImageChatError(
          400,
          "UNSUPPORTED_IMAGE_TYPE",
          "Upload a JPEG, PNG, or WebP image."
        )
      );
    }
    return callback(null, true);
  },
});

export class ImageChatError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ImageChatError";
    this.status = status;
    this.code = code;
  }
}

export const discardUploadedImage = (file) => {
  if (Buffer.isBuffer(file?.buffer)) file.buffer.fill(0);
  if (file) file.buffer = null;
};

const hasValidSignature = (buffer, mimeType) => {
  if (!Buffer.isBuffer(buffer)) return false;
  if (mimeType === "image/jpeg") {
    return buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  }
  if (mimeType === "image/png") {
    const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    return buffer.length >= 8 && signature.every((byte, index) => buffer[index] === byte);
  }
  if (mimeType === "image/webp") {
    return (
      buffer.length >= 12 &&
      buffer.subarray(0, 4).toString("ascii") === "RIFF" &&
      buffer.subarray(8, 12).toString("ascii") === "WEBP"
    );
  }
  return false;
};

const sleep = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

export const analyzeImage = async ({
  file,
  prompt,
  conversationMessages = [],
  modeConfig,
  apiKey,
  referer,
}) => {
  if (!file) {
    throw new ImageChatError(400, "IMAGE_REQUIRED", "Choose an image to analyze.");
  }
  if (!hasValidSignature(file.buffer, file.mimetype)) {
    discardUploadedImage(file);
    throw new ImageChatError(
      400,
      "INVALID_IMAGE_FILE",
      "The selected file is not a valid JPEG, PNG, or WebP image."
    );
  }

  let imageDataUrl = `data:${file.mimetype};base64,${file.buffer.toString("base64")}`;
  const textPrompt = String(prompt || "").trim() || "Describe this image.";
  const history = conversationMessages.slice(0, -1);

  const requestVisionModel = async (isRetry = false) => {
    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": referer,
        "X-Title": "NeXT AI",
      },
      body: JSON.stringify({
        model: VISION_MODEL,
        messages: [
          {
            role: "system",
            content:
              "You are NeXT AI, the image-capable assistant inside Modelwise. " +
              "Analyze the supplied image and answer the user's request directly. " +
              `Identify yourself only as NeXT AI. ${modeConfig.instruction}`,
          },
          ...(isRetry
            ? [{ role: "system", content: NEXT_AI_RETRY_INSTRUCTION }]
            : []),
          ...history,
          {
            role: "user",
            content: [
              { type: "text", text: textPrompt },
              { type: "image_url", image_url: { url: imageDataUrl } },
            ],
          },
        ],
        max_tokens: modeConfig.maxOutputTokens,
        provider: { allow_fallbacks: true },
      }),
    });
    const data = await response.json().catch(() => ({}));
    return { response, data };
  };

  try {
    let result = await requestVisionModel();
    if (!result.response.ok && (result.response.status === 429 || result.response.status >= 500)) {
      const retryAfter = Number(result.response.headers.get("retry-after") || 0);
      if (Number.isFinite(retryAfter) && retryAfter > 0) {
        await sleep(Math.min(2000, retryAfter * 1000));
      }
      result = await requestVisionModel(true);
    }
    if (!result.response.ok) {
      console.error("OpenRouter vision request failed:", result.data.error || result.data);
      throw new ImageChatError(
        503,
        "VISION_PROVIDER_UNAVAILABLE",
        "NeXT AI image analysis is temporarily unavailable. Please try again in a moment."
      );
    }

    let content = result.data.choices?.[0]?.message?.content || "";
    if (isSafetyClassificationOnly(content)) {
      result = await requestVisionModel(true);
      if (!result.response.ok) {
        throw new ImageChatError(
          503,
          "VISION_PROVIDER_UNAVAILABLE",
          "NeXT AI image analysis is temporarily unavailable. Please try again in a moment."
        );
      }
      content = result.data.choices?.[0]?.message?.content || "";
    }

    return {
      response:
        !content || isSafetyClassificationOnly(content)
          ? NEXT_AI_RESPONSE_FALLBACK
          : content,
      usage: result.data.usage || null,
      model: result.data.model || VISION_MODEL,
    };
  } finally {
    discardUploadedImage(file);
    imageDataUrl = "";
  }
};
