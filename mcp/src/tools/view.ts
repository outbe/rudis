import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { rememberMarkets } from "../oracle/markets.js";
import type { Ctx } from "../chain.js";
import {
  CONTRACTS,
  PROPOSAL_STATUS,
  type ProposalStatusName,
  proposalStatusCode,
  proposalStatusName,
} from "../registry.js";
import { handler, ok, view } from "./util.js";

const addr = z.string().describe("0x-prefixed address");
const wwd = z.number().int().describe("WorldwideDay as YYYYMMDD, e.g. 20260601");

/**
 * Normalise the proposal status.
 *
 * `format.ts` already renders `status` as `{code, name}` for `IGovernance.*`
 * structs; this only backfills the name when a caller hands over a raw code.
 */
function annotateProposal(p: unknown): Record<string, unknown> {
  const r = { ...(p as Record<string, unknown>) };
  if (typeof r.status === "number" || typeof r.status === "bigint") {
    const code = Number(r.status);
    r.status = { code, name: proposalStatusName(code) };
  }
  return r;
}

export function registerViewTools(server: McpServer, ctx: Ctx): void {
  // --- generic escape hatch: any view method of any precompile ---------------
  server.tool(
    "contract_call",
    `Call any view/pure method on a Rudis precompile and get decoded, human-readable output. ` +
      `\`contract\` is a registry name (${Object.keys(CONTRACTS).join(", ")}) or a 0x address. ` +
      `\`method\` is the function name; \`args\` are its arguments in order (numbers/strings).`,
    {
      contract: z.string(),
      method: z.string(),
      args: z.array(z.any()).optional(),
    },
    handler(async ({ contract, method, args }) =>
      ok(await view(ctx, contract, method, args ?? [])),
    ),
  );

  // --- Tribute ---------------------------------------------------------------
  server.tool(
    "tribute_get",
    "Tribute metadata by token id: owner + decoded attributes (worldwide_day, currency, amounts).",
    { id: z.string().describe("Tribute token id as a uint256 (decimal or 0x hex)") },
    handler(async ({ id }) => {
      const [metadata, owner] = await Promise.all([
        view(ctx, "tribute", "tokenURI", [id]),
        view(ctx, "tribute", "ownerOf", [id]),
      ]);
      return ok({ tokenId: id, owner, metadata });
    }),
  );

  server.tool(
    "tributes_by_owner",
    "List Tribute token ids owned by an address.",
    { owner: addr },
    handler(async ({ owner }) => ok(await view(ctx, "tribute", "getTributesByOwner", [owner]))),
  );

  server.tool(
    "tributes_by_day",
    "List Tribute token ids recorded for a WorldwideDay.",
    { worldwide_day: wwd },
    handler(async ({ worldwide_day }) =>
      ok(await view(ctx, "tribute", "getTributesByDay", [worldwide_day])),
    ),
  );

  server.tool(
    "worldwide_day_totals",
    "Aggregate Tribute totals for a WorldwideDay (count, nominal amount, sealed).",
    { worldwide_day: wwd },
    handler(async ({ worldwide_day }) =>
      ok(await view(ctx, "tribute", "getDayTotals", [worldwide_day])),
    ),
  );

  // --- Nod -------------------------------------------------------------------
  server.tool(
    "nod_get",
    "Nod NFT data by token id (decoded) plus parsed tokenURI metadata.",
    { id: z.string().describe("Nod token id as a uint256 (decimal or 0x hex)") },
    handler(async ({ id }) => {
      const [data, metadata] = await Promise.all([
        view(ctx, "nod", "nodData", [id]),
        view(ctx, "nod", "tokenURI", [id]),
      ]);
      return ok({ nodId: id, data, metadata });
    }),
  );

  server.tool(
    "nods_by_owner",
    "List Nod token ids owned by an address (Nod has no bulk getter, so this " +
      "enumerates balanceOf -> tokenOfOwnerByIndex).",
    { owner: addr },
    handler(async ({ owner }) => {
      const balance = Number(await view(ctx, "nod", "balanceOf", [owner]));
      const ids: unknown[] = [];
      for (let i = 0; i < balance; i++) {
        ids.push(await view(ctx, "nod", "tokenOfOwnerByIndex", [owner, i]));
      }
      return ok({ owner, count: balance, nodIds: ids });
    }),
  );

  // --- Gem -------------------------------------------------------------------
  server.tool(
    "gem_get",
    "Gem NFT status by token id (decoded: type, state, load, prices, currency, issued).",
    { id: z.string().describe("Gem token id (decimal or 0x hex)") },
    handler(async ({ id }) => ok(await view(ctx, "gem", "getGemStatus", [BigInt(id)]))),
  );

  server.tool(
    "gem_position_get",
    "Parked-Intex position terms by id: merchant, source series, remaining capacity, " +
      "the entry/floor prices its gems are anchored to, both currencies and when it was parked.",
    { id: z.string().describe("Position token id (decimal or 0x hex)") },
    handler(async ({ id }) =>
      ok(await view(ctx, "gemfactory", "getPosition", [BigInt(id)])),
    ),
  );

  server.tool(
    "gem_settle_quote",
    "What settling a gem with a given asset costs, and which of the gem's two currencies " +
      "that asset settles on. `payableUnits` is in the asset's own minor units.",
    {
      id: z.string().describe("Gem token id (decimal or 0x hex)"),
      asset: addr.describe("Settlement stablecoin the holder intends to pay with"),
    },
    handler(async ({ id, asset }) =>
      ok(await view(ctx, "gemfactory", "quoteSettlement", [BigInt(id), asset])),
    ),
  );

  server.tool(
    "gems_by_owner",
    "List Gems owned by an address with decoded status for each (Gem has no bulk getter, " +
      "so this enumerates balanceOf -> tokenOfOwnerByIndex -> getGemStatus).",
    { owner: addr },
    handler(async ({ owner }) => {
      const balance = Number(await view(ctx, "gem", "balanceOf", [owner]));
      const gems: unknown[] = [];
      for (let i = 0; i < balance; i++) {
        const tokenId = await view(ctx, "gem", "tokenOfOwnerByIndex", [owner, i]);
        gems.push(await view(ctx, "gem", "getGemStatus", [BigInt(tokenId as string)]));
      }
      return ok({ owner, count: balance, gems });
    }),
  );

  // --- Balances --------------------------------------------------------------
  server.tool(
    "gratis_balance",
    "Gratis balance + pledged amount for an account (in rudis).",
    { account: addr },
    handler(async ({ account }) => {
      const [balance, pledged] = await Promise.all([
        view(ctx, "gratis", "balanceOf", [account]),
        view(ctx, "gratis", "pledgedOf", [account]),
      ]);
      return ok({ account, balance, pledged });
    }),
  );

  server.tool(
    "promis_balance",
    "Promis balance for an account (in rudis).",
    { account: addr },
    handler(async ({ account }) => ok(await view(ctx, "promis", "balanceOf", [account]))),
  );

  // Per-account fidelity index is now encrypted and owner-signature-gated, so a
  // read-only MCP tool cannot fetch it. Expose the public synthetic-max ceiling
  // (`maxFidelityIndexAt`) instead - the upper bound on any account's RCFI at a
  // given time, in decayed days.
  server.tool(
    "fidelity_max_index",
    "Public synthetic-maximum Fidelity Index (saturating RCFI ceiling) at a Unix timestamp, in decayed days.",
    { timestamp: z.number().int().describe("Unix timestamp (seconds)") },
    handler(async ({ timestamp }) =>
      ok(await view(ctx, "fidelity", "maxFidelityIndexAt", [timestamp])),
    ),
  );

  server.tool(
    "agentreward_claimable",
    "Claimable AgentReward balance for an account (in rudis), both pools summed.",
    { account: addr },
    handler(async ({ account }) =>
      ok(await view(ctx, "agentreward", "getClaimableBalance", [account])),
    ),
  );

  server.tool(
    "agentreward_pool_claimable",
    "Claimable AgentReward balance for an account in one pool (0 = WAA, 1 = SRA), in rudis.",
    { account: addr, pool: z.number().int().min(0).max(1).describe("0 = WAA, 1 = SRA") },
    handler(async ({ account, pool }) =>
      ok(await view(ctx, "agentreward", "getPoolClaimableBalance", [account, pool])),
    ),
  );

  // --- Metadosis / WorldwideDay ---------------------------------------------
  server.tool(
    "worldwide_days_offering",
    "WorldwideDays currently in OFFERING status (the days a tribute offer can target).",
    {},
    handler(async () => {
      const wwds = (await view(ctx, "metadosis", "getWorldwideDaysByStatus", [2])) as {
        wwds: { wwd: number; date: string }[];
      };
      return ok(wwds);
    }),
  );

  server.tool(
    "worldwide_day_get",
    "Full lifecycle state of a WorldwideDay (status, type, period timestamps, VWAP).",
    { worldwide_day: wwd },
    handler(async ({ worldwide_day }) =>
      ok(await view(ctx, "metadosis", "getWorldwideDay", [worldwide_day])),
    ),
  );

  // --- Oracle ----------------------------------------------------------------
  server.tool(
    "currency_pairs",
    "All oracle price pairs (index, base, quote, the decimals each side is quoted in, active).",
    {},
    handler(async () => {
      // The oracle enumerates its registry by index rather than returning the
      // whole table, so the table is assembled here.
      const count = Number(await view(ctx, "oracle", "getPairCount", []));
      const indices = Array.from({ length: count }, (_, i) => i + 1);
      const pairs = await Promise.all(
        indices.map(async (index) => {
          const pair = (await view(ctx, "oracle", "getPairByIndex", [index])) as {
            base: string;
            quote: string;
            baseScale: number;
            quoteScale: number;
          };
          const active = await view(ctx, "oracle", "isVoteTarget", [pair.base, pair.quote]);
          return {
            index,
            base: pair.base,
            quote: pair.quote,
            baseScale: Number(pair.baseScale),
            quoteScale: Number(pair.quoteScale),
            active,
          };
        }),
      );
      rememberMarkets(
        ctx.chain.id,
        pairs.map((p) => [p.base, p.quote, p.baseScale, p.quoteScale] as const),
      );
      return ok(pairs);
    }),
  );

  server.tool(
    "currency_rate",
    "Latest exchange rate for a base/quote pair.",
    { base: z.string(), quote: z.string() },
    handler(async ({ base, quote }) =>
      ok(await view(ctx, "oracle", "getExchangeRate", [base, quote])),
    ),
  );

  server.tool(
    "currency_rate_vwap",
    "VWAP for a base/quote pair. With lookback_seconds uses the rolling window; otherwise the day VWAP.",
    {
      base: z.string(),
      quote: z.string(),
      lookback_seconds: z.number().int().optional(),
    },
    handler(async ({ base, quote, lookback_seconds }) =>
      ok(
        lookback_seconds === undefined
          ? await view(ctx, "oracle", "getDayVwap", [base, quote])
          : await view(ctx, "oracle", "getVwap", [base, quote, lookback_seconds]),
      ),
    ),
  );

  // --- Validators ------------------------------------------------------------
  server.tool(
    "validators",
    "Active validator set + counts and current epoch.",
    {},
    handler(async () => {
      const [active, count, epoch] = await Promise.all([
        view(ctx, "validatorset", "getActiveValidators", []),
        view(ctx, "validatorset", "activeValidatorCount", []),
        view(ctx, "validatorset", "getEpochNumber", []),
      ]);
      return ok({ active, activeCount: count, epoch });
    }),
  );

  server.tool(
    "validator_get",
    "Full validator record by address (stake, status, miss counters, epoch heights).",
    { address: addr },
    handler(async ({ address }) =>
      ok(await view(ctx, "validatorset", "validatorByAddress", [address])),
    ),
  );

  server.tool(
    "staking_info",
    "Stake delegated to a validator and total staked.",
    { validator: addr },
    handler(async ({ validator }) => {
      const [stake, total] = await Promise.all([
        view(ctx, "staking", "getStake", [validator]),
        view(ctx, "staking", "getTotalStaked", []),
      ]);
      return ok({ validator, stake, total });
    }),
  );

  // --- Governance (canon, meta-canon, OIP, GIP) - read-only -----------------
  server.tool(
    "metacanon_get",
    "The meta-canon: current text + version + keccak hash (constitutional layer regulating the canon).",
    {},
    handler(async () => ok(await view(ctx, "governance", "getMetaCanon", []))),
  );

  server.tool(
    "canon_get",
    "The canon: current text + version + keccak hash (active protocol norms).",
    {},
    handler(async () => ok(await view(ctx, "governance", "getCanon", []))),
  );

  const proposalId = z.string().describe("Proposal id (decimal or 0x hex), 1-based");

  server.tool(
    "oip_get",
    "One Outbe Improvement Proposal by id: author, status, blocks, text hash, and full text.",
    { id: proposalId },
    handler(async ({ id }) =>
      ok(annotateProposal(await view(ctx, "governance", "getOip", [BigInt(id)]))),
    ),
  );

  server.tool(
    "gip_get",
    "One Governance Improvement Proposal by id: author, status, blocks, text hash, and full text.",
    { id: proposalId },
    handler(async ({ id }) =>
      ok(annotateProposal(await view(ctx, "governance", "getGip", [BigInt(id)]))),
    ),
  );

  // Index-backed, PAGINATED listing (metadata only - omits the full text).
  // Exactly one of `author` / `status` must be given; each maps to a dedicated
  // on-chain index (get*ByAuthor / get*ByStatus). Returns `total` (the whole
  // bucket size) plus the requested `[offset, offset+limit)` page.
  const listFilter = {
    author: z.string().optional().describe("0x address - list this author's proposals"),
    status: z
      .enum(PROPOSAL_STATUS)
      .optional()
      .describe(`proposal status: ${PROPOSAL_STATUS.join(" | ")}`),
    offset: z.number().int().min(0).optional().describe("page start (default 0)"),
    limit: z.number().int().min(1).max(1000).optional().describe("page size (default 100, max 1000)"),
  };

  async function listProposals(
    kind: "Oip" | "Gip",
    args: { author?: string; status?: ProposalStatusName; offset?: number; limit?: number },
  ): Promise<{ total: number; offset: number; limit: number; items: unknown[] }> {
    const { author, status } = args;
    if ((author === undefined) === (status === undefined)) {
      throw new Error(
        `provide exactly one of \`author\` or \`status\` (${PROPOSAL_STATUS.join("|")})`,
      );
    }
    const offset = args.offset ?? 0;
    const limit = args.limit ?? 100;
    const byAuthor = author !== undefined;
    const suffix = byAuthor ? "ByAuthor" : "ByStatus";
    const key = byAuthor ? author : proposalStatusCode(status as ProposalStatusName);
    const [metas, total] = await Promise.all([
      view(ctx, "governance", `get${kind}s${suffix}`, [key, offset, limit]) as Promise<
        unknown[]
      >,
      view(ctx, "governance", `${kind.toLowerCase()}Count${suffix}`, [key]),
    ]);
    return { total: Number(total), offset, limit, items: metas.map(annotateProposal) };
  }

  server.tool(
    "oip_list",
    "List OIPs by index, paginated (metadata only - omits the full text). Give `author` " +
      "(their OIPs) or `status` (a proposal status name), plus optional `offset`/`limit`.",
    listFilter,
    handler(async (args) => {
      const { total, offset, limit, items } = await listProposals("Oip", args);
      return ok({ total, offset, limit, oips: items });
    }),
  );

  server.tool(
    "gip_list",
    "List GIPs by index, paginated (metadata only - omits the full text). Give `author` " +
      "(their GIPs) or `status` (a proposal status name), plus optional `offset`/`limit`.",
    listFilter,
    handler(async (args) => {
      const { total, offset, limit, items } = await listProposals("Gip", args);
      return ok({ total, offset, limit, gips: items });
    }),
  );
}
