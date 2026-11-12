import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  BLOCK_MESSAGE,
  chatCompletionReply,
  firewallEnvironment,
  runPiTurn,
  startClassifier,
  startLoopback,
  toolCallReply,
  toolResults,
  writeAgentDirectory,
} from "./native-acceptance/harness.ts";

test("pi -e . applies malicious tool-result and assistant replacements through the host", { timeout: 20_000 }, async () => {
  const classifier = startClassifier((hook) => hook === "tool_response" || hook === "llm_output");
  const classifierLoopback = await classifier;
  const model = await startLoopback<Record<string, unknown>>(async (body) => toolResults(body).length > 0
    ? chatCompletionReply({ role: "assistant", content: "PI_RAW_ASSISTANT_OUTPUT" }, "stop")
    : toolCallReply("printf PI_RAW_TOOL_RESULT"));
  try {
    const agentDirectory = path.join(await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-cli-")), "agent");
    await writeAgentDirectory(agentDirectory, model.url);
    const turn = await runPiTurn(
      path.join(process.cwd(), "node_modules", ".bin", "pi"),
      ["-e", "."],
      process.cwd(),
      firewallEnvironment(agentDirectory, classifierLoopback.url),
      "exercise every Pi Firewall output boundary",
    );

    assert.equal(model.requests.length, 2);
    const providerToolResult = toolResults(model.requests[1] ?? {}).join("\n");
    assert.doesNotMatch(providerToolResult, /PI_RAW_TOOL_RESULT/u);
    assert.ok(providerToolResult.includes(BLOCK_MESSAGE));

    const transcriptToolResult = turn.messages.find((message) => message.role === "toolResult");
    const transcriptAssistant = [...turn.messages].reverse().find((message) => message.role === "assistant");
    const finalMessage = [...turn.events].reverse().find((event) => event.type === "message_end");
    for (const [value, raw] of [
      [transcriptToolResult, /PI_RAW_TOOL_RESULT/u],
      [transcriptAssistant, /PI_RAW_ASSISTANT_OUTPUT/u],
      [finalMessage, /PI_RAW_ASSISTANT_OUTPUT/u],
    ] as const) {
      assert.ok(value);
      assert.doesNotMatch(JSON.stringify(value), raw);
      assert.ok(JSON.stringify(value).includes(BLOCK_MESSAGE));
    }

    assert.deepEqual(classifier.attempts.map((attempt) => attempt.hook), [
      "user_input", "tool_call", "tool_response", "llm_output",
    ]);
  } finally {
    await Promise.all([model.close(), classifierLoopback.close()]);
  }
});
