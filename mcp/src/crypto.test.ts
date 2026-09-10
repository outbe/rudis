import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildPayload } from "./crypto.js";

function decodePayload(amount_base: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(buildPayload({ creator: "0x01", amount_base }))) as Record<
    string,
    unknown
  >;
}

const cases = JSON.parse(
  readFileSync(new URL("../../testdata/tribute/canonical-amounts-v1.json", import.meta.url), "utf8"),
) as { accepted_base: string[]; rejected_base: string[] };

test("tribute payload emits canonical base with a zero six-decimal remainder", () => {
  for (const amount of cases.accepted_base) {
    const payload = decodePayload(amount);
    assert.equal(payload.amount_base, amount);
    assert.equal(payload.amount_atto, "0");
  }
});

test("tribute payload rejects non-canonical unsigned u64 base values", () => {
  for (const amount of cases.rejected_base) {
    assert.throws(() => decodePayload(amount), `accepted amount_base ${JSON.stringify(amount)}`);
  }
});
