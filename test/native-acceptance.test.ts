import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  BLOCK_MESSAGE,
  CLASSIFY_DEADLINE_MS,
  LIVE_ATTACK,
  evaluateScenario,
  liveBlocker,
  overallStatus,
  sameFiles,
  scenariosFor,
  startClassifier,
  type ClassifierRequest,
  type Scenario,
} from "./native-acceptance/harness.ts";

const [allow, preBlock, responseBlock] = scenariosFor(false) as [Scenario, Scenario, Scenario];
const classified = (...hooks: string[]): ClassifierRequest[] => hooks.map((hook) => ({
  hook, decision: "allow", outcome: "success", durationMs: 1, marker: null,
}));

test("allow passes only when the effect exists and the tool output reached the model", () => {
  const observation = {
    effectPresent: true,
    classifierRequests: classified("user_input", "tool_call", "tool_response"),
    toolResultsSeenByModel: [allow.output],
  };
  assert.equal(evaluateScenario(allow, observation).status, "PASS");
  assert.equal(evaluateScenario(allow, { ...observation, effectPresent: false }).status, "FAIL");
  assert.equal(evaluateScenario(allow, { ...observation, toolResultsSeenByModel: [BLOCK_MESSAGE] }).status, "FAIL");
  assert.equal(evaluateScenario(allow, { ...observation, classifierRequests: [] }).status, "FAIL");
});

test("pre-tool-block fails when the effect exists or the tool ran", () => {
  const observation = {
    effectPresent: false,
    classifierRequests: classified("user_input", "tool_call"),
    toolResultsSeenByModel: [BLOCK_MESSAGE],
  };
  assert.deepEqual(
    { status: evaluateScenario(preBlock, observation).status, effect: evaluateScenario(preBlock, observation).effect_present },
    { status: "PASS", effect: false },
  );
  assert.equal(evaluateScenario(preBlock, { ...observation, effectPresent: true }).status, "FAIL");
  assert.equal(evaluateScenario(preBlock, { ...observation, classifierRequests: classified("tool_call", "tool_response") }).status, "FAIL");
});

test("tool-response-block fails when the poison reaches the model", () => {
  const observation = {
    effectPresent: true,
    classifierRequests: classified("user_input", "tool_call", "tool_response"),
    toolResultsSeenByModel: [BLOCK_MESSAGE],
  };
  assert.equal(evaluateScenario(responseBlock, observation).status, "PASS");
  assert.equal(evaluateScenario(responseBlock, { ...observation, toolResultsSeenByModel: [responseBlock.output] }).status, "FAIL");
});

test("live runs skip the pre-tool scenario and attribute classifier-caused failures", async () => {
  const live = scenariosFor(true);
  assert.deepEqual(live.map((scenario) => scenario.id), ["allow", "tool-response-block"]);
  const liveResponseBlock = live[1] as Scenario;
  assert.equal(liveResponseBlock.output, LIVE_ATTACK);

  const upstream = { prediction: "MALICIOUS", mode: "shadow", governance: { action: "allow" } };
  const classifier = startClassifier(() => false, {
    url: "https://classifier.invalid/classify",
    key: "unit-test-key",
    fetchImpl: async () => Response.json(upstream),
  });
  const loopback = await classifier;
  try {
    await fetch(loopback.url, { method: "POST", body: JSON.stringify({ hook: "tool_response", text: LIVE_ATTACK }) });
  } finally {
    await loopback.close();
  }
  const [attempt] = classifier.attempts as [ClassifierRequest];
  assert.deepEqual(attempt.upstream, { prediction: "MALICIOUS", mode: "shadow", action: "allow" });
  assert.ok(!JSON.stringify(classifier.attempts).includes("unit-test-key"));
  assert.equal(liveBlocker(liveResponseBlock, attempt), "tenant_not_in_block_mode");
  assert.equal(liveBlocker(liveResponseBlock, { ...attempt, durationMs: CLASSIFY_DEADLINE_MS }), "classifier_exceeded_plugin_deadline");
  assert.equal(liveBlocker(liveResponseBlock, { ...attempt, decision: "allow" }), "classifier_did_not_flag_attack");
  assert.equal(liveBlocker(allow, attempt), "classifier_flagged_benign_control");
  assert.equal(liveBlocker(liveResponseBlock, { ...attempt, upstream: { ...upstream, mode: "block", action: "block" } }), undefined);
  assert.equal(liveBlocker(liveResponseBlock, classified("tool_response")[0]), undefined);

  const leaked = evaluateScenario(liveResponseBlock, {
    effectPresent: true,
    classifierRequests: [attempt],
    toolResultsSeenByModel: [LIVE_ATTACK],
  });
  assert.deepEqual({ status: leaked.status, blocker: leaked.blocker }, { status: "BLOCKED", blocker: "tenant_not_in_block_mode" });
});

test("live classifier transport failures are recorded without upstream detail", async () => {
  const classifier = startClassifier(() => false, {
    url: "https://classifier.invalid/classify",
    key: "unit-test-key",
    fetchImpl: async () => new Response("upstream detail", { status: 503 }),
  });
  const loopback = await classifier;
  try {
    const response = await fetch(loopback.url, { method: "POST", body: JSON.stringify({ hook: "tool_response" }) });
    assert.equal(response.status, 502);
  } finally {
    await loopback.close();
  }
  assert.deepEqual(classifier.attempts.map((attempt) => [attempt.outcome, attempt.decision]), [["http_error", null]]);
  assert.equal(liveBlocker(responseBlock, classifier.attempts[0]), "classifier_http_error");
});

test("overall status requires every scenario and installed candidate bytes", () => {
  const pass = { id: "allow", status: "PASS", effect_present: true, checks: {} } as const;
  assert.equal(overallStatus([pass, pass, pass], 3, true), "PASS");
  assert.equal(overallStatus([pass, pass], 3, true), "FAIL");
  assert.equal(overallStatus([pass, pass, pass], 3, false), "FAIL");
  assert.equal(overallStatus([pass, { ...pass, status: "BLOCKED" }], 2, true), "BLOCKED");
  assert.equal(overallStatus([{ ...pass, status: "FAIL" }, { ...pass, status: "BLOCKED" }], 2, true), "FAIL");
});

test("installed files must equal the packed files, ignoring installed dependencies", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-native-test-"));
  for (const side of ["packed", "installed"]) {
    await mkdir(path.join(root, side, "src"), { recursive: true });
    await writeFile(path.join(root, side, "src", "runtime.ts"), "export {};\n");
  }
  await mkdir(path.join(root, "installed", "node_modules", "dependency"), { recursive: true });
  await writeFile(path.join(root, "installed", "node_modules", "dependency", "index.js"), "");
  assert.equal(sameFiles(path.join(root, "packed"), path.join(root, "installed")), true);
  await writeFile(path.join(root, "installed", "src", "runtime.ts"), "export const changed = true;\n");
  assert.equal(sameFiles(path.join(root, "packed"), path.join(root, "installed")), false);
  await mkdir(path.join(root, "empty"));
  assert.equal(sameFiles(path.join(root, "empty"), path.join(root, "empty")), false);
  assert.throws(() => sameFiles(path.join(root, "absent"), path.join(root, "installed")), { code: "ENOENT" });
});
