import test from "node:test";
import assert from "node:assert/strict";
import { createSafetyGate, isSafetyClassificationOnly } from "../src/lib/chat/response-validation.js";

const feedAll = (gate, chunks) => chunks.map((chunk) => gate.feed(chunk)).join("");

test("safety gate withholds a response that is only safety labels, streamed in pieces", () => {
  const gate = createSafetyGate();
  const emitted = feedAll(gate, ["User Safety: safe\n", "Response Safety: safe"]);
  assert.equal(emitted, "");
  const result = gate.finish();
  assert.equal(result.isSafetyOnly, true);
  assert.equal(result.remaining, "");
});

test("safety gate releases as soon as a disqualifying line arrives, streamed in pieces", () => {
  const gate = createSafetyGate();
  const emitted = feedAll(gate, [
    "User Safety: safe\n",
    "Sure, here is the answer to your question: 2 + 2 equals 4.",
  ]);
  const result = gate.finish();
  assert.ok((emitted + result.remaining).includes("Sure, here is the answer"));
  assert.equal(result.isSafetyOnly, false);
});

test("safety gate releases a normal reply with no safety-label lines at all", () => {
  const gate = createSafetyGate();
  const emitted = feedAll(gate, ["The capital of France is Paris."]);
  const finish = gate.finish();
  assert.equal(emitted + finish.remaining, "The capital of France is Paris.");
  assert.equal(finish.isSafetyOnly, false);
});

test("safety gate matches isSafetyClassificationOnly on the fully-buffered case", () => {
  const safetyOnlyText = "User Safety: safe\nResponse Safety: safe";
  assert.equal(isSafetyClassificationOnly(safetyOnlyText), true);

  const gate = createSafetyGate();
  feedAll(gate, [safetyOnlyText]);
  assert.equal(gate.finish().isSafetyOnly, true);
});

test("safety gate releases once more than 4 matching lines accumulate", () => {
  const gate = createSafetyGate();
  const lines = Array.from({ length: 5 }, () => "User Safety: safe\n");
  const emitted = feedAll(gate, lines);
  assert.ok(emitted.length > 0);
  assert.equal(gate.finish().isSafetyOnly, false);
});
