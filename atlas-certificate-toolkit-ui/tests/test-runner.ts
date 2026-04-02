import assert from "node:assert/strict";

import { extractErrorMessage } from "../src/utils/errorResponse.js";
import { formatExpiration } from "../src/utils/jobExpiration.js";

async function run() {
  const jsonMessage = await extractErrorMessage(
    "application/json; charset=utf-8",
    async () => ({ error: "BAD_REQUEST", message: "Mensagem amigavel" }),
    async () => "fallback"
  );
  assert.equal(jsonMessage, "Mensagem amigavel");

  const jsonCode = await extractErrorMessage(
    "application/json",
    async () => ({ error: "BAD_REQUEST" }),
    async () => "fallback"
  );
  assert.equal(jsonCode, "BAD_REQUEST");

  const textMessage = await extractErrorMessage(
    "text/plain",
    async () => null,
    async () => "Falha textual"
  );
  assert.equal(textMessage, "Falha textual");

  assert.equal(
    formatExpiration("2026-04-02T10:00:00.000Z", Date.parse("2026-04-02T10:05:00.000Z")),
    "Arquivos expirados."
  );
  assert.equal(
    formatExpiration("2026-04-02T10:20:00.000Z", Date.parse("2026-04-02T10:05:00.000Z")),
    "Expira em cerca de 15 min."
  );

  console.log("Frontend tests passed.");
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
