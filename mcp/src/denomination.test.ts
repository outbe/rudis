import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import test from "node:test";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  type AbiParameter,
  type AbiFunction,
  type Chain,
  type Hex,
  type PublicClient,
  type WalletClient,
  decodeFunctionData,
  zeroHash,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  type Ctx,
  createCtx,
  formatNativeAmount,
  parseNativeAmount,
} from "./chain.js";
import { formatParam, humanizeReturn } from "./format.js";
import { humanizeOrder } from "./intent/format.js";
import { resolveContract } from "./registry.js";
import { registerSignTools } from "./tools/sign.js";
import { wcoenLockAmount } from "./tools/intex.js";
import { view as readHumanizedView } from "./tools/util.js";

async function withChainIdRpc<T>(chainId: number, run: (rpcUrl: string) => Promise<T>): Promise<T> {
  const rpc = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const payload = JSON.parse(Buffer.concat(chunks).toString("utf8")) as
      | { id: number }
      | { id: number }[];
    const reply = (item: { id: number }) => ({
      jsonrpc: "2.0",
      id: item.id,
      result: `0x${chainId.toString(16)}`,
    });
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(Array.isArray(payload) ? payload.map(reply) : reply(payload)));
  });
  rpc.listen(0, "127.0.0.1");
  await once(rpc, "listening");

  try {
    const address = rpc.address();
    assert(address && typeof address === "object");
    return await run(`http://127.0.0.1:${address.port}`);
  } finally {
    rpc.close();
    await once(rpc, "close");
  }
}

test("Rudis chain metadata declares its public identity and eighteen native decimals", async () => {
  await withChainIdRpc(70_860_602, async (rpcUrl) => {
    const ctx = await createCtx(rpcUrl);
    assert.equal(ctx.chain.id, 70_860_602);
    assert.equal(ctx.chain.name, "Rehearsal Network");
    assert.deepEqual(ctx.chain.nativeCurrency, { name: "rudis", symbol: "rudis", decimals: 18 });
  });
});

test("BSC chain metadata retains eighteen native decimals", async () => {
  await withChainIdRpc(97, async (rpcUrl) => {
    const ctx = await createCtx(rpcUrl);
    assert.deepEqual(ctx.chain.nativeCurrency, { name: "BNB", symbol: "BNB", decimals: 18 });
  });
});

test("unknown external EVM chain metadata retains eighteen native decimals", async () => {
  await withChainIdRpc(42_161, async (rpcUrl) => {
    const ctx = await createCtx(rpcUrl);
    assert.deepEqual(ctx.chain.nativeCurrency, { name: "Ether", symbol: "ETH", decimals: 18 });
  });
});

test("network-native parsing and formatting follows chain metadata", () => {
  const outbe = { nativeCurrency: { decimals: 18 } } as Chain;
  const bsc = { nativeCurrency: { decimals: 18 } } as Chain;

  assert.equal(parseNativeAmount(outbe, "1.5"), 1_500_000_000_000_000_000n);
  assert.equal(formatNativeAmount(outbe, 1_500_000_000_000_000_000n), "1.5");
  assert.equal(parseNativeAmount(bsc, "1.5"), 1_500_000_000_000_000_000n);
  assert.equal(formatNativeAmount(bsc, 1_500_000_000_000_000_000n), "1.5");
});

test("MCP Intex converts protocol-6 PROMIS lock math to native-18 WCOEN", () => {
  assert.equal(wcoenLockAmount(2n, 1_500_000n, 500_000n), 1_500_000_000_000_000_000n);
});

test("MCP formats native monetary fields at scale18 and leaves dimensionless FP18 alone", () => {
  assert.deepEqual(
    formatParam(
      { name: "balance", type: "uint256" } as AbiParameter,
      1_500_000_000_000_000_000n,
      { contractName: "agentreward", functionName: "getClaimableBalance" },
    ),
    { raw: "1500000000000000000", value: "1.5" },
  );
  assert.deepEqual(
    formatParam(
      { name: "", type: "uint256" } as AbiParameter,
      1_500_000_000_000_000_000n,
      { contractName: "agentreward", functionName: "getPoolClaimableBalance" },
    ),
    { raw: "1500000000000000000", value: "1.5" },
  );
  // A claim returns a Gem id, which is not an amount and must stay unscaled.
  assert.equal(
    formatParam({ name: "gemId", type: "uint256" } as AbiParameter, 1_500_000_000_000_000_000n, {
      contractName: "agentreward",
      functionName: "claimReward",
    }),
    "1500000000000000000",
  );
  assert.deepEqual(
    formatParam(
      { name: "rewardBand", type: "uint256" } as AbiParameter,
      20_000_000_000_000_000n,
    ),
    { raw: "20000000000000000", value: "0.02" },
  );
});

test("MCP formats Credis and Oracle annual rates with six decimals", () => {
  const position = {
    name: "position",
    type: "tuple",
    internalType: "struct ICredis.Position",
    components: [{ name: "currencyRate", type: "uint256" }],
  } as AbiParameter;
  assert.deepEqual(formatParam(position, { currencyRate: 43_000n }), {
    currencyRate: { raw: "43000", value: "0.043" },
  });

  const getPolicyRate = {
    type: "function",
    name: "getPolicyRate",
    stateMutability: "view",
    inputs: [{ name: "isoCode", type: "uint16" }],
    outputs: [{ name: "rate", type: "uint256" }],
  } as AbiFunction;
  assert.deepEqual(humanizeReturn(getPolicyRate, 43_000n), {
    rate: { raw: "43000", value: "0.043" },
  });

  assert.deepEqual(
    formatParam({ name: "rate", type: "uint256" } as AbiParameter, 43_000_000_000_000_000n),
    { raw: "43000000000000000", value: "0.043" },
  );
});

test("MCP Oracle views apply six decimals from the real call context", async () => {
  const coen = "0x0000000000000000000000000000000000000000";
  const iso840 = "0x00000000000000000000000000000000000cc840";
  const erc20 = "0x1111111111111111111111111111111111111111";
  const invalidIsoLike = "0x00000000000000000000000000000000000cc8a0";

  const read = async (method: string, args: unknown[], result: unknown) => {
    const ctx = {
      rpcUrl: "http://unused.invalid",
      chain: { id: 70_860_602 } as Chain,
      publicClient: {
        readContract: async () => result,
      } as unknown as PublicClient,
    } satisfies Ctx;
    return readHumanizedView(ctx, "oracle", method, args);
  };

  assert.deepEqual(await read("getExchangeRate", [coen, iso840], 1_234_567n), {
    rate: { raw: "1234567", value: "1.234567" },
  });
  assert.deepEqual(await read("getExchangeRate", [iso840, coen], 765_432n), {
    rate: { raw: "765432", value: "0.765432" },
  });
  assert.deepEqual(await read("getVwap", [coen, iso840, 3_600], 1_111_111n), {
    vwap: { raw: "1111111", value: "1.111111" },
  });
  assert.deepEqual(await read("getRudisExchangeRateFor", [840], 1_234_567n), {
    rate: { raw: "1234567", value: "1.234567" },
  });
  assert.deepEqual(await read("getPolicyRate", [840], 43_000n), {
    rate: { raw: "43000", value: "0.043" },
  });
  assert.deepEqual(
    await read("getExchangeRate", [erc20, iso840], 1_000_000_000_000_000_000n),
    { rate: { raw: "1000000000000000000", value: "1" } },
  );
  assert.deepEqual(
    await read("getExchangeRate", [coen, invalidIsoLike], 1_000_000_000_000_000_000n),
    { rate: { raw: "1000000000000000000", value: "1" } },
  );
});

test("MCP Oracle aggregate views format each market row independently", async () => {
  const coen = "0x0000000000000000000000000000000000000000";
  const iso840 = "0x00000000000000000000000000000000000cc840";
  const erc20 = "0x1111111111111111111111111111111111111111";
  const bases = [coen, erc20];
  const quotes = [iso840, iso840];
  const scaledValues = [1_234_567n, 2_000_000_000_000_000_000n];
  const formattedValues = [
    { raw: "1234567", value: "1.234567" },
    { raw: "2000000000000000000", value: "2" },
  ];

  const read = async (method: string, args: unknown[], result: unknown) => {
    const ctx = {
      rpcUrl: "http://unused.invalid",
      chain: { id: 70_860_602 } as Chain,
      publicClient: {
        readContract: async () => result,
      } as unknown as PublicClient,
    } satisfies Ctx;
    return (await readHumanizedView(ctx, "oracle", method, args)) as Record<string, unknown>;
  };

  const aggregateVote = await read("getAggregateVote", [erc20], [
    true,
    bases,
    quotes,
    scaledValues,
    scaledValues,
  ]);
  assert.deepEqual(aggregateVote.rates, formattedValues);
  assert.deepEqual(aggregateVote.volumes, formattedValues);

  const snapshotHistory = await read("getAllPriceSnapshotHistory", [2], [
    [1n, 2n],
    [100n, 200n],
    bases,
    quotes,
    scaledValues,
    scaledValues,
  ]);
  assert.deepEqual(snapshotHistory.rates, formattedValues);
  assert.deepEqual(snapshotHistory.volumes, formattedValues);

  const twaps = await read("getTwaps", [3_600], [bases, quotes, scaledValues, [3_600n, 3_600n]]);
  assert.deepEqual(twaps.twaps, formattedValues);

  const worldwide = await read("getWorldwideDayVwap", [100, 200], [
    bases,
    quotes,
    scaledValues,
    [100n, 100n],
  ]);
  assert.deepEqual(worldwide.vwaps, formattedValues);

  const snapshot = await read("getWorldwideDayVwapSnapshot", [20260818], [
    100n,
    200n,
    bases,
    quotes,
    scaledValues,
    [100n, 100n],
  ]);
  assert.deepEqual(snapshot.vwaps, formattedValues);

  const scurve = await read("getAllScurveData", [], [
    [coen],
    [iso840],
    [20260818n],
    [1_234_567n],
  ]);
  assert.deepEqual(scurve.peakPrices, [{ raw: "1234567", value: "1.234567" }]);
});

test("MCP signed COEN inputs convert whole amounts to eighteen-decimal units", async () => {
  type ToolHandler = (args: Record<string, unknown>) => Promise<unknown>;
  const handlers = new Map<string, ToolHandler>();
  const server = {
    tool(name: string, ...args: unknown[]) {
      handlers.set(name, args.at(-1) as ToolHandler);
    },
  } as unknown as McpServer;
  const account = privateKeyToAccount(generatePrivateKey());
  const sent: { data: Hex; value: bigint }[] = [];
  const ctx = {
    rpcUrl: "http://unused.invalid",
    chain: { id: 1, nativeCurrency: { name: "COEN", symbol: "COEN", decimals: 18 } } as Chain,
    publicClient: {} as PublicClient,
    account,
    walletClient: {
      sendTransaction: async (transaction: { data: Hex; value: bigint }) => {
        sent.push(transaction);
        return `0x${"11".repeat(32)}` as Hex;
      },
    } as WalletClient,
  } satisfies Ctx;
  registerSignTools(server, ctx);

  const cases = [
    {
      tool: "staking_stake",
      contract: "staking",
      args: { validator: account.address, amount: "1.5", wait: false },
      amountIndex: 1,
      value: 1_500_000_000_000_000_000n,
    },
    {
      tool: "staking_unstake",
      contract: "staking",
      args: { amount: "1.5", wait: false },
      amountIndex: 0,
      value: 0n,
    },
    {
      tool: "agentreward_claim",
      contract: "agentreward",
      args: { pool: 0, amount: "1.5", wait: false },
      amountIndex: 1,
      value: 0n,
    },
  ] as const;

  for (const item of cases) {
    const callback = handlers.get(item.tool);
    assert(callback, `${item.tool} was registered`);
    await callback(item.args);
    const transaction = sent.at(-1);
    assert(transaction, `${item.tool} submitted a transaction`);
    const entry = resolveContract(item.contract);
    const decoded = decodeFunctionData({ abi: entry.abi, data: transaction.data });
    assert.equal(decoded.args?.[item.amountIndex], 1_500_000_000_000_000_000n, item.tool);
    assert.equal(transaction.value, item.value, `${item.tool} msg.value`);
  }
});

test("external intent amounts retain their existing 18-decimal presentation", () => {
  const order = humanizeOrder({
    sender: zeroHash,
    recipient: zeroHash,
    inputToken: zeroHash,
    outputToken: zeroHash,
    amountIn: 1_000_000_000_000_000_000n,
    amountOut: 500_000_000_000_000_000n,
    senderNonce: 1n,
    originDomain: 1,
    destinationDomain: 2,
    destinationSettler: zeroHash,
    fillDeadline: 1,
    data: "0x",
  });

  assert.equal(order.amountIn.value1e18, "1");
  assert.equal(order.amountOut.value1e18, "0.5");
});
