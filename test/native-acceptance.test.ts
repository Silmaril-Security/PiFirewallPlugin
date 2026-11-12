import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  BLOCK_MESSAGE,
  CLASSIFY_DEADLINE_MS,
  LIVE_ATTACK,
  evaluateScenario,
  liveBlocker,
  liveClassifierFrom,
  overallStatus,
  runPiTurn,
  sameFiles,
  scenariosFor,
  startCandidateRegistry,
  startClassifier,
  startLoopback,
  type ClassifierRequest,
  type Scenario,
} from "./native-acceptance/harness.ts";

const HARNESS = fileURLToPath(new URL("./native-acceptance/harness.ts", import.meta.url));
const [allow, preBlock, responseBlock] = scenariosFor(false) as [Scenario, Scenario, Scenario];
const [liveAllow, liveResponseBlock] = scenariosFor(true) as [Scenario, Scenario];
const classified = (decisions: Record<string, "allow" | "block">): ClassifierRequest[] => Object.entries(decisions)
  .map(([hook, decision]) => ({ hook, decision, outcome: "success", durationMs: 1, marker: null }));
const upstreamOf = (request: ClassifierRequest, mode: string | null = null): ClassifierRequest => ({
  ...request,
  upstream: { prediction: request.decision === "block" ? "MALICIOUS" : "BENIGN", mode, action: "allow" },
});
const allowed = {
  effectPresent: true,
  classifierRequests: classified({ user_input: "allow", tool_call: "allow", tool_response: "allow", llm_output: "allow" }),
  toolResultsSeenByModel: [allow.output],
};
const responseBlocked = {
  effectPresent: true,
  classifierRequests: classified({ user_input: "allow", tool_call: "allow", tool_response: "block", llm_output: "allow" }),
  toolResultsSeenByModel: [BLOCK_MESSAGE],
};
const failedAt = (requests: ClassifierRequest[], hook: string, failure: Partial<ClassifierRequest>): ClassifierRequest[] => requests
  .map((request) => request.hook === hook ? { ...request, ...failure } : request);
const verdict = (result: { status: string; blocker?: string }): Array<string | undefined> => [result.status, result.blocker];

test("allow passes only when the effect exists and the tool output reached the model", () => {
  assert.equal(evaluateScenario(allow, allowed).status, "PASS");
  assert.equal(evaluateScenario(allow, { ...allowed, effectPresent: false }).status, "FAIL");
  assert.equal(evaluateScenario(allow, { ...allowed, toolResultsSeenByModel: [BLOCK_MESSAGE] }).status, "FAIL");
  assert.equal(evaluateScenario(allow, { ...allowed, classifierRequests: [] }).status, "FAIL");
});

test("pre-tool-block fails when the effect exists or the tool ran", () => {
  const observation = {
    effectPresent: false,
    classifierRequests: classified({ user_input: "allow", tool_call: "block", llm_output: "allow" }),
    toolResultsSeenByModel: [BLOCK_MESSAGE],
  };
  const result = evaluateScenario(preBlock, observation);
  assert.deepEqual({ status: result.status, effect: result.effect_present }, { status: "PASS", effect: false });
  assert.equal(evaluateScenario(preBlock, { ...observation, effectPresent: true }).status, "FAIL");
  assert.equal(evaluateScenario(preBlock, { ...observation, classifierRequests: classified({ tool_call: "block", tool_response: "allow" }) }).status, "FAIL");
  assert.equal(evaluateScenario(preBlock, { ...observation, classifierRequests: classified({ tool_call: "allow" }) }).status, "FAIL");
});

test("tool-response-block fails when the poison reaches the model", () => {
  assert.equal(evaluateScenario(responseBlock, responseBlocked).status, "PASS");
  assert.equal(evaluateScenario(responseBlock, { ...responseBlocked, toolResultsSeenByModel: [responseBlock.output] }).status, "FAIL");
  assert.equal(evaluateScenario(responseBlock, { ...responseBlocked, classifierRequests: allowed.classifierRequests }).status, "FAIL");
});

test("a classification the plugin never received cannot pass, even when every effect is as expected", () => {
  for (const [failure, blocker] of [
    [{ outcome: "http_error", decision: null }, "classifier_http_error"],
    [{ outcome: "invalid_response", decision: null }, "classifier_invalid_response"],
    [{ outcome: "transport_error", decision: null }, "classifier_transport_error"],
    [{ outcome: "transport_error", decision: null, durationMs: 10_000 }, "classifier_exceeded_plugin_deadline"],
    [{ durationMs: CLASSIFY_DEADLINE_MS }, "classifier_exceeded_plugin_deadline"],
  ] as const) {
    for (const hook of ["user_input", "tool_call", "tool_response"]) {
      assert.deepEqual(
        verdict(evaluateScenario(allow, { ...allowed, classifierRequests: failedAt(allowed.classifierRequests, hook, failure) })),
        ["BLOCKED", blocker],
      );
    }
    assert.deepEqual(
      verdict(evaluateScenario(responseBlock, {
        ...responseBlocked,
        classifierRequests: failedAt(responseBlocked.classifierRequests, "tool_response", failure),
        toolResultsSeenByModel: [responseBlock.output],
      })),
      ["BLOCKED", blocker],
    );
  }
});

test("live runs skip the pre-tool scenario and use the customer attack as the poison", () => {
  assert.deepEqual([liveAllow.id, liveResponseBlock.id], ["allow", "tool-response-block"]);
  assert.equal(liveResponseBlock.output, LIVE_ATTACK);
});

test("the upstream mode never vetoes a live run the plugin enforced under its own block mode", () => {
  for (const mode of [null, "shadow", "warn", "block"]) {
    const requests = responseBlocked.classifierRequests.map((request) => upstreamOf(request, mode));
    assert.equal(liveBlocker(liveResponseBlock, requests), undefined);
    assert.deepEqual(verdict(evaluateScenario(liveResponseBlock, { ...responseBlocked, classifierRequests: requests })), ["PASS", undefined]);
    assert.deepEqual(
      verdict(evaluateScenario(liveResponseBlock, { ...responseBlocked, classifierRequests: requests, toolResultsSeenByModel: [LIVE_ATTACK] })),
      ["FAIL", undefined],
    );
  }
});

test("live verdicts that contradict the scenario are attributed to the classifier", () => {
  const unflagged = allowed.classifierRequests.map((request) => upstreamOf(request));
  assert.deepEqual(
    verdict(evaluateScenario(liveResponseBlock, { ...allowed, classifierRequests: unflagged, toolResultsSeenByModel: [LIVE_ATTACK] })),
    ["BLOCKED", "classifier_did_not_flag_attack"],
  );
  const flagged = classified({ user_input: "allow", tool_call: "block", llm_output: "allow" }).map((request) => upstreamOf(request));
  assert.deepEqual(
    verdict(evaluateScenario(liveAllow, { effectPresent: false, classifierRequests: flagged, toolResultsSeenByModel: [BLOCK_MESSAGE] })),
    ["BLOCKED", "classifier_flagged_benign_control"],
  );
  assert.equal(liveBlocker(liveAllow, unflagged), undefined);
  assert.equal(liveBlocker(allow, classified({ tool_call: "block" })), undefined);
});

test("the live classifier proxy records the upstream verdict without the customer key", async () => {
  const classifier = await startClassifier(() => false, {
    url: "https://classifier.invalid/classify",
    key: "unit-test-key",
    fetchImpl: async () => Response.json({ prediction: "MALICIOUS", governance: { action: "allow" } }),
  });
  try {
    const response = await fetch(classifier.url, { method: "POST", body: JSON.stringify({ hook: "tool_response", text: LIVE_ATTACK }) });
    assert.deepEqual(await response.json(), { prediction: "MALICIOUS", governance: { action: "allow" } });
  } finally {
    await classifier.close();
  }
  assert.deepEqual(classifier.attempts.map(({ durationMs: _durationMs, ...attempt }) => attempt), [{
    hook: "tool_response",
    decision: "block",
    outcome: "success",
    marker: null,
    upstream: { prediction: "MALICIOUS", mode: null, action: "allow" },
  }]);
  assert.ok(!JSON.stringify(classifier.attempts).includes("unit-test-key"));
});

test("live classifier failures are recorded without upstream detail", async () => {
  const replies: Array<() => Promise<Response>> = [
    async () => new Response("upstream detail", { status: 503 }),
    async () => new Response("upstream detail"),
    async () => Response.json({ prediction: "UNKNOWN" }),
    async () => Promise.reject(new Error("upstream detail")),
  ];
  let upstream = replies[0] as () => Promise<Response>;
  const classifier = await startClassifier(() => false, {
    url: "https://classifier.invalid/classify",
    key: "unit-test-key",
    fetchImpl: () => upstream(),
  });
  try {
    for (const reply of replies) {
      upstream = reply;
      const response = await fetch(classifier.url, { method: "POST", body: JSON.stringify({ hook: "tool_response" }) });
      assert.equal(response.status, 502);
    }
  } finally {
    await classifier.close();
  }
  assert.deepEqual(classifier.attempts.map((attempt) => [attempt.outcome, attempt.decision, attempt.upstream]), [
    ["http_error", null, undefined],
    ["invalid_response", null, undefined],
    ["invalid_response", null, undefined],
    ["transport_error", null, undefined],
  ]);
  assert.ok(!JSON.stringify(classifier.attempts).includes("upstream detail"));
});

test("a live verdict that outlives the plugin's request is still measured before the scenario is judged", async () => {
  const classifier = await startClassifier(() => false, {
    url: "https://classifier.invalid/classify",
    key: "unit-test-key",
    fetchImpl: async () => {
      await new Promise((resolve) => setTimeout(resolve, 150));
      return Response.json({ prediction: "BENIGN" });
    },
  });
  try {
    await assert.rejects(
      fetch(classifier.url, { method: "POST", body: JSON.stringify({ hook: "tool_call" }), signal: AbortSignal.timeout(25) }),
      { name: "TimeoutError" },
    );
    assert.deepEqual(classifier.attempts.map((attempt) => [attempt.outcome, attempt.durationMs]), [["transport_error", 0]]);
    await classifier.settled();
  } finally {
    await classifier.close();
  }
  const [attempt] = classifier.attempts as [ClassifierRequest];
  assert.deepEqual([attempt.outcome, attempt.decision, attempt.durationMs >= 100], ["success", "allow", true]);
});

test("a loopback exchange that fails drops its connection and fails the run when settled", async () => {
  const loopback = await startLoopback<Record<string, unknown>>(async () => ({ status: 200, type: "application/json", text: "{}" }));
  try {
    await assert.rejects(fetch(loopback.url, { method: "POST", body: "not json" }));
    await assert.rejects(loopback.settled(), SyntaxError);
  } finally {
    await loopback.close();
  }
});

test("live acceptance requires an HTTPS endpoint and a customer key", () => {
  const configured = { CUSTOMER_NATIVE_API_URL: "https://classifier.invalid/classify", CUSTOMER_NATIVE_API_KEY: "unit-test-key" };
  assert.deepEqual(liveClassifierFrom(configured), { url: configured.CUSTOMER_NATIVE_API_URL, key: "unit-test-key" });
  for (const env of [
    {},
    { ...configured, CUSTOMER_NATIVE_API_KEY: "" },
    { ...configured, CUSTOMER_NATIVE_API_URL: "" },
    { ...configured, CUSTOMER_NATIVE_API_URL: "not a url" },
    { ...configured, CUSTOMER_NATIVE_API_URL: "http://classifier.invalid/classify" },
  ]) {
    assert.throws(() => liveClassifierFrom(env), { name: "live_classifier_not_configured" });
  }
});

test("an unconfigured live run still writes a failing receipt that names the cause", { timeout: 30_000 }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-native-test-"));
  const receiptPath = path.join(root, "nested", "live-receipt.json");
  try {
    await assert.rejects(promisify(execFile)(process.execPath, ["--import", "tsx", HARNESS], {
      env: { PATH: process.env.PATH, HOME: root, CUSTOMER_NATIVE_CLASSIFIER: "live", NATIVE_ACCEPTANCE_RECEIPT: receiptPath },
    }), { code: 1 });
    const receipt = JSON.parse(await readFile(receiptPath, "utf8")) as Record<string, unknown>;
    assert.deepEqual(
      [receipt.schema, receipt.status, receipt.classifier, receipt.error, receipt.scenarios],
      ["silmaril.native-acceptance.v1", "FAIL", "live", "live_classifier_not_configured", []],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a host that exits or stalls rejects the turn and is not left running", { timeout: 30_000 }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-native-test-"));
  const pidFile = path.join(root, "host.pid");
  const host = (script: string): Promise<unknown> => runPiTurn(
    process.execPath,
    ["-e", script, "--"],
    root,
    { PATH: process.env.PATH },
    "unanswered prompt",
    { turnMs: 1_000, terminateMs: 250 },
  );
  try {
    await assert.rejects(host("process.exit(3)"), { name: "host_exited" });
    await assert.rejects(host("process.stdin.resume(); process.stdout.write('{\"type\":\"response\",\"id\":\"native-prompt\",\"success\":true}\\n'); setTimeout(() => process.exit(0), 100)"), { name: "host_exited" });
    await assert.rejects(
      host(`require("node:fs").writeFileSync(${JSON.stringify(pidFile)}, String(process.pid)); process.on("SIGTERM", () => undefined); setInterval(() => undefined, 1_000)`),
      { name: "host_turn_timeout" },
    );
    const stalledHost = Number(await readFile(pidFile, "utf8"));
    assert.throws(() => process.kill(stalledHost, 0), { code: "ESRCH" });
    await assert.rejects(runPiTurn(path.join(root, "absent-host"), [], root, {}, "unanswered prompt"), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("overall status requires every scenario and installed candidate bytes", () => {
  const pass = { id: "allow", status: "PASS", effect_present: true, checks: {} } as const;
  assert.equal(overallStatus([pass, pass, pass], 3, true), "PASS");
  assert.equal(overallStatus([pass, pass], 3, true), "FAIL");
  assert.equal(overallStatus([], 3, true), "FAIL");
  assert.equal(overallStatus([pass, pass, pass], 3, false), "FAIL");
  assert.equal(overallStatus([pass, { ...pass, status: "BLOCKED" }], 2, false), "FAIL");
  assert.equal(overallStatus([pass, { ...pass, status: "BLOCKED" }], 2, true), "BLOCKED");
  assert.equal(overallStatus([{ ...pass, status: "FAIL" }, { ...pass, status: "BLOCKED" }], 2, true), "FAIL");
});

test("installed files must equal the packed files, ignoring installed dependencies", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-native-test-"));
  try {
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
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the candidate registry serves the packed tarball and sends every other package to the public registry host", async () => {
  const tarball = Buffer.from("candidate tarball bytes");
  const registry = await startCandidateRegistry({ name: "@silmaril-security/pi-firewall-plugin", version: "0.0.0" }, tarball);
  try {
    const metadata = await (await fetch(`${registry.url}/@silmaril-security%2fpi-firewall-plugin`)).json() as {
      versions: Record<string, { dist: { tarball: string } }>;
    };
    const served = await fetch(metadata.versions["0.0.0"]?.dist.tarball ?? "");
    assert.deepEqual(Buffer.from(await served.arrayBuffer()), tarball);
    for (const [route, location] of [
      ["/@silmaril-security%2fsdk", "https://registry.npmjs.org/@silmaril-security%2fsdk"],
      ["//registry.invalid/package", "https://registry.npmjs.org/registry.invalid/package"],
    ] as const) {
      const redirect = await fetch(`${registry.url}${route}`, { redirect: "manual" });
      assert.deepEqual([redirect.status, redirect.headers.get("location")], [302, location]);
    }
  } finally {
    await registry.close();
  }
});
