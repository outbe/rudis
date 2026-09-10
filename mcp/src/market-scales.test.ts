import assert from "node:assert/strict";
import test from "node:test";
import { humanizeReturn } from "./format.js";
import { marketMap, scaleOf, type PairRow } from "./oracle/markets.js";

const COEN = "0x0000000000000000000000000000000000000000";
const USD = "0x00000000000000000000000000000000000cc840";
const TOKEN_A = "0x1111111111111111111111111111111111111111";
const TOKEN_B = "0x2222222222222222222222222222222222222222";

const ROWS: PairRow[] = [
  [COEN, USD, 6, 6],
  [TOKEN_A, TOKEN_B, 18, 18],
];

const RATE_FN = {
  type: "function",
  name: "getExchangeRate",
  stateMutability: "view",
  inputs: [
    { name: "base", type: "address" },
    { name: "quote", type: "address" },
  ],
  outputs: [{ name: "rate", type: "uint256" }],
} as const;

test("the registry answers for a market registered in either direction", () => {
  const markets = marketMap(ROWS);
  assert.equal(scaleOf(markets, COEN, USD), 6);
  assert.equal(scaleOf(markets, USD, COEN), 6);
  assert.equal(scaleOf(markets, TOKEN_A, TOKEN_B), 18);
});

test("a reversed quote reports the scale of the side it was asked in", () => {
  const markets = marketMap([[COEN, USD, 6, 18]]);
  assert.equal(scaleOf(markets, COEN, USD), 18);
  assert.equal(scaleOf(markets, USD, COEN), 6);
});

test("an unregistered market and a malformed address answer nothing", () => {
  const markets = marketMap(ROWS);
  assert.equal(scaleOf(markets, COEN, TOKEN_A), undefined);
  assert.equal(scaleOf(markets, "not-an-address", USD), undefined);
  assert.equal(scaleOf(markets, 840, USD), undefined);
});

test("rates render in the scale the registry reports", () => {
  const markets = marketMap(ROWS);
  const scaleFor = (base: unknown, quote: unknown) => scaleOf(markets, base, quote);

  const coenUsd = humanizeReturn(RATE_FN, 8_090_000n, { oracleArgs: [COEN, USD], scaleFor });
  assert.deepEqual(coenUsd, { rate: { raw: "8090000", value: "8.09" } });

  const generic = humanizeReturn(RATE_FN, 8_090_000_000_000_000_000n, {
    oracleArgs: [TOKEN_A, TOKEN_B],
    scaleFor,
  });
  assert.deepEqual(generic, { rate: { raw: "8090000000000000000", value: "8.09" } });
});

test("an unreadable registry falls back to the local rule", () => {
  const empty = marketMap([]);
  const scaleFor = (base: unknown, quote: unknown) => scaleOf(empty, base, quote);

  const coenUsd = humanizeReturn(RATE_FN, 8_090_000n, { oracleArgs: [COEN, USD], scaleFor });
  assert.deepEqual(coenUsd, { rate: { raw: "8090000", value: "8.09" } });
});
