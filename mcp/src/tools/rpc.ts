import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Ctx } from "../chain.js";
import { toJson } from "../format.js";
import { handler, ok } from "./util.js";

export function registerRpcTools(server: McpServer, ctx: Ctx): void {
  server.tool(
    "chain_info",
    "Chain id, latest block number, gas price and base fee for the connected outbe-chain node.",
    {},
    handler(async () => {
      const [chainId, blockNumber, gasPrice, block] = await Promise.all([
        ctx.publicClient.getChainId(),
        ctx.publicClient.getBlockNumber(),
        ctx.publicClient.getGasPrice(),
        ctx.publicClient.getBlock({ blockTag: "latest" }),
      ]);
      return ok({
        rpcUrl: ctx.rpcUrl,
        chainId,
        blockNumber: blockNumber.toString(),
        gasPriceWei: gasPrice.toString(),
        baseFeePerGasWei: block.baseFeePerGas?.toString() ?? null,
        signer: ctx.account?.address ?? null,
      });
    }),
  );

  server.tool(
    "block_get",
    "Fetch a block by number or tag (default latest). Pass `block` as a number, hex, or 'latest'/'finalized'.",
    { block: z.union([z.number(), z.string()]).optional() },
    handler(async ({ block }) => {
      const b =
        block === undefined || block === "latest" || block === "finalized" || block === "pending"
          ? await ctx.publicClient.getBlock({ blockTag: (block as any) ?? "latest" })
          : await ctx.publicClient.getBlock({ blockNumber: BigInt(block) });
      return ok(JSON.parse(toJson(b)));
    }),
  );

  server.tool(
    "transaction_get",
    "Fetch a transaction by hash.",
    { hash: z.string() },
    handler(async ({ hash }) => {
      const tx = await ctx.publicClient.getTransaction({ hash: hash as `0x${string}` });
      return ok(JSON.parse(toJson(tx)));
    }),
  );

  server.tool(
    "transaction_receipt_get",
    "Fetch a transaction receipt by hash, including status (success/reverted), gas used and logs.",
    { hash: z.string() },
    handler(async ({ hash }) => {
      const r = await ctx.publicClient.getTransactionReceipt({
        hash: hash as `0x${string}`,
      });
      return ok(JSON.parse(toJson(r)));
    }),
  );
}
