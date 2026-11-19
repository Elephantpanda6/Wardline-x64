import assert from "node:assert/strict";
import test from "node:test";
import {
  ApprovalRequiredError,
  DeniedError,
  encodeIpcFrame,
  unwrapCheckedResponse,
  WardlineClient,
} from "../src/index.ts";

test("encodes IPC frame and unwraps typed errors", () => {
  const frame = encodeIpcFrame({ type: "health" });
  const len = frame.readUInt32LE(0);
  assert.equal(len, frame.length - 4);
  assert.deepEqual(JSON.parse(frame.subarray(4).toString("utf8")), { type: "health" });

  assert.throws(
    () =>
      unwrapCheckedResponse({
        status: "approval_required",
        ticket_id: "t-123",
        action_digest_hex: "deadbeef",
        scope_key: "fs_write:x",
        reason: "needs review",
      }),
    ApprovalRequiredError,
  );

  assert.throws(
    () =>
      unwrapCheckedResponse({
        status: "denied",
        reason: "blocked",
        remediation: "check policy",
      }),
    DeniedError,
  );

  const client = new WardlineClient();
  assert.ok(client);
});
