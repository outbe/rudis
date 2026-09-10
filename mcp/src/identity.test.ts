import assert from "node:assert/strict";
import test from "node:test";
import { decodeEventLog, encodeAbiParameters, encodeEventTopics, encodeFunctionData, zeroAddress } from "viem";
import { resolveToken, symbolForAddress } from "./intent/tokens.js";
import { intentRouter } from "./intent/registry.js";
import { bridgeDstChainId, intexAddress, ORIGIN_ROUTER_ABI } from "./intex/registry.js";

function configured(values: Record<string, string | undefined>, run: () => void): void {
  const before = Object.fromEntries(Object.keys(values).map((key) => [key, process.env[key]]));
  const apply = (entries: Record<string, string | undefined>) => {
    for (const [key, value] of Object.entries(entries)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
  try { apply(values); run(); } finally { apply(before); }
}

test("exported Intex ABI encodes wrudis and decodes the renamed JSON field", () => {
  assert.equal(encodeFunctionData({ abi: ORIGIN_ROUTER_ABI, functionName: "wrudis" }), "0xa1b14d44");
  assert.throws(() => encodeFunctionData({ abi: ORIGIN_ROUTER_ABI, functionName: "wcoen" }));
  const wrapped = "0x1111111111111111111111111111111111111111";
  const [topic] = encodeEventTopics({ abi: ORIGIN_ROUTER_ABI, eventName: "ProceedsRouteSet" });
  assert.equal(typeof topic, "string");
  if (typeof topic !== "string") throw new Error("expected a concrete event signature");
  const event = decodeEventLog({
    abi: ORIGIN_ROUTER_ABI,
    topics: [topic],
    data: encodeAbiParameters([{ type: "address" }, { type: "address" }], [zeroAddress, wrapped]),
  });
  assert.deepEqual(event.args, { tokenBridge: zeroAddress, wrudis: wrapped });
});

test("Rudis resolves native aliases without assuming old token deployments", () => {
  configured({ OUTBE_INTENT_TOKENS: undefined }, () => {
    const network = { name: "rudis-rehearsal", chainId: 70860602 };
    for (const symbol of ["rudis", "RUDIS", "wrudis"]) {
      assert.deepEqual(resolveToken(symbol, network), { address: zeroAddress, symbol: "rudis" });
    }
    assert.equal(symbolForAddress(zeroAddress, network.chainId), "rudis");
    assert.throws(() => resolveToken("USD", network), /not available/);
    assert.throws(() => resolveToken("wrudis", { name: "bsc-testnet", chainId: 97 }), /not available/);
  });
});

test("cross-chain tools require confirmed deployments and retain fixed precompiles", () => {
  configured({ OUTBE_INTENT_ROUTER: undefined, OUTBE_INTEX_ADDRESSES: undefined }, () => {
    assert.throws(() => intentRouter(), /OUTBE_INTENT_ROUTER/);
    assert.throws(() => intexAddress("rudis-rehearsal", "originRouter"), /OUTBE_INTEX_ADDRESSES/);
    assert.throws(() => intexAddress("bsc-testnet", "paymentToken"), /OUTBE_INTEX_ADDRESSES/);
    assert.equal(intexAddress("rudis-rehearsal", "factory"), "0x0000000000000000000000000000000000001015");
    assert.equal(bridgeDstChainId("bsc-testnet"), 70860602);
  });
  const address = "0x1111111111111111111111111111111111111111";
  configured({
    OUTBE_INTENT_ROUTER: address,
    OUTBE_INTEX_ADDRESSES: JSON.stringify({ "bsc-testnet": { paymentToken: address } }),
    OUTBE_INTENT_TOKENS: JSON.stringify({ wrudis: { 97: address } }),
  }, () => {
    assert.equal(intentRouter(), address);
    assert.equal(intexAddress("bsc-testnet", "paymentToken"), address);
    assert.deepEqual(resolveToken("wrudis", { name: "bsc-testnet", chainId: 97 }), { address, symbol: "rudis" });
  });
});
