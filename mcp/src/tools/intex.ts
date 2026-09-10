import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  type AbiEvent,
  type Account,
  type Address,
  type Chain,
  type Hex,
  type PublicClient,
  type WalletClient,
  encodeFunctionData,
  formatUnits,
  getAbiItem,
  getAddress,
  maxUint256,
  pad,
  parseUnits,
} from "viem";
import { z } from "zod";
import { type Ctx, createCtx, formatNativeAmount } from "../chain.js";
import { handler, ok } from "./util.js";
import {
  AUCTION_ABI,
  DESIS_ABI,
  ERC20_ABI,
  ESCROW_ABI,
  FACTORY_ABI,
  type IntexAddresses,
  NETWORKS,
  NFT_ABI,
  NFT_BRIDGE_ABI,
  INTEX_ABI,
  ORIGIN_ROUTER_ABI,
  VAULT_ROUTER_ABI,
  bridgeDstChainId,
  intexAddress,
} from "../intex/registry.js";
import { auctionStage, desisStage, epochIso, intexState, intexStatus, isActiveStage, lockStatus, fromSeriesId, toSeriesId } from "../intex/format.js";
import { commitHash, revealBidTypedData } from "../intex/bid.js";
import { POW_DIFFICULTY, grindNonce } from "../intex/pow.js";

/**
 * Intex participant tools: auction commit/reveal, escrow funding, NFT holdings,
 * the series ledger, the BSC->outbe bridge, and settlement/Promis on Rehearsal Network.
 *
 * Domain (addresses, ABIs, decoders) lives in src/intex/. Networks come from the
 * NETWORKS table; a resolved network reuses the connected `ctx` when chain ids
 * match, else opens a fresh client via createCtx - same shape as src/tools/intent.ts.
 *
 * Read tools work without a key; signing tools require OUTBE_PRIVATE_KEY.
 */

interface Network {
  name: string;
  chainId: number;
  chain: Chain;
  client: PublicClient;
  wallet?: WalletClient;
}

const SCALE_1E6 = 1_000_000n;
const NATIVE_UNITS_PER_PROTOCOL_UNIT = 1_000_000_000_000n;

/** Convert the protocol-6 auction basis and rate into the native-18 wrudis lock. */
export function wcoenLockAmount(quantity: bigint, promisLoadProtocol: bigint, bidRate: bigint): bigint {
  return ((quantity * promisLoadProtocol * bidRate) / SCALE_1E6) * NATIVE_UNITS_PER_PROTOCOL_UNIT;
}

const PROMIS_MINED_EVENT = getAbiItem({ abi: FACTORY_ABI, name: "PromisMined" }) as AbiEvent;

// Auction ids are worldwide days (yyyymmdd), one per day; the auction runs weeks
// after its day, so active ids sit up to ~26 days in the past. Discovery probes
// getAuctionStage across a date window - a few cheap point reads - rather than
// scanning logs, which public RPCs range-limit.
const DEFAULT_DAYS_BACK = 30;
const DEFAULT_DAYS_AHEAD = 2;
const DAY_MS = 86_400_000;

function priced(minor: bigint) {
  return { raw: minor.toString(), value: formatUnits(minor, 6), scale: "1e6 ISO stable-unit" };
}

function ymdToDate(ymd: number): Date {
  return new Date(Date.UTC(Math.floor(ymd / 10000), (Math.floor(ymd / 100) % 100) - 1, ymd % 100));
}
function dateToYmd(dt: Date): number {
  return dt.getUTCFullYear() * 10000 + (dt.getUTCMonth() + 1) * 100 + dt.getUTCDate();
}
function todayYmd(): number {
  return dateToYmd(new Date());
}
function ymdShift(ymd: number, days: number): number {
  return dateToYmd(new Date(ymdToDate(ymd).getTime() + days * DAY_MS));
}
function ymdRange(from: number, to: number): number[] {
  const out: number[] = [];
  for (const dt = ymdToDate(from); dateToYmd(dt) <= to; dt.setUTCDate(dt.getUTCDate() + 1)) out.push(dateToYmd(dt));
  return out;
}

export function registerIntexTools(server: McpServer, ctx: Ctx): void {
  const pk = process.env.OUTBE_PRIVATE_KEY;
  const netCache = new Map<string, Network>();

  async function resolveNetwork(spec: string): Promise<Network> {
    const s = spec.trim().toLowerCase();
    const def = NETWORKS.find((d) => d.name.toLowerCase() === s || String(d.chainId) === s);
    if (!def) {
      throw new Error(`unknown network "${spec}"; supported: ${NETWORKS.map((d) => d.name).join(", ")}`);
    }
    const cached = netCache.get(def.name);
    if (cached) return cached;
    const rpc = def.rpc ?? process.env.OUTBE_RPC;
    if (def.chainId !== ctx.chain.id && !rpc) {
      throw new Error(`Set OUTBE_RPC to connect to ${def.name}`);
    }
    const c = def.chainId === ctx.chain.id ? ctx : await createCtx(rpc!, pk);
    if (c.chain.id !== def.chainId) {
      throw new Error(`RPC for ${def.name} returned chain ID ${c.chain.id}; expected ${def.chainId}`);
    }
    const n: Network = {
      name: def.name,
      chainId: c.chain.id,
      chain: c.chain,
      client: c.publicClient,
      wallet: c.walletClient,
    };
    netCache.set(def.name, n);
    return n;
  }

  /** The address arg or the configured signer; throws if neither is available. */
  function whoever(explicit?: string): Address {
    if (explicit) return getAddress(explicit);
    if (ctx.account) return ctx.account.address;
    throw new Error("no address given and no signer configured - pass an explicit address");
  }

  function addr(n: Network, key: keyof IntexAddresses): Address {
    return intexAddress(n.name, key);
  }

  function requireAccount(): Account {
    if (!ctx.account) {
      throw new Error("signing requires a key - set OUTBE_PRIVATE_KEY in the MCP server env");
    }
    return ctx.account;
  }

  async function estimateGas(n: Network, to: Address, data: Hex, value: bigint): Promise<bigint> {
    const est = await n.client.estimateGas({ account: ctx.account?.address, to, data, value });
    return (est * 130n) / 100n;
  }

  async function send(n: Network, to: Address, data: Hex, value: bigint, gas: bigint): Promise<Hex> {
    const account = requireAccount();
    if (!n.wallet) throw new Error(`no signer for ${n.name}`);
    return n.wallet.sendTransaction({ account, chain: n.chain, to, data, value, gas });
  }

  /** Submit a tx and, unless wait===false, wait for and summarize its receipt. */
  async function submit(n: Network, to: Address, data: Hex, value: bigint, wait?: boolean) {
    const gas = await estimateGas(n, to, data, value);
    const hash = await send(n, to, data, value, gas);
    if (wait === false) return { txHash: hash, status: "submitted" as const };
    const r = await n.client.waitForTransactionReceipt({ hash, timeout: 180_000 });
    return { txHash: hash, status: r.status, blockNumber: r.blockNumber.toString(), gasUsed: r.gasUsed.toString() };
  }

  // A bid is a RATE: the fraction of the protocol-6 per-Intex PROMIS load that
  // the bidder will pay, as 1e6 fixed-point. The result crosses into native-18
  // wrudis only at the escrow boundary. Payment-token meta is cached per network.
  const metaCache = new Map<string, { decimals: number; symbol: string }>();
  async function paymentMeta(n: Network): Promise<{ decimals: number; symbol: string }> {
    const cached = metaCache.get(n.name);
    if (cached) return cached;
    const token = addr(n, "paymentToken");
    const [decimals, symbol] = (await Promise.all([
      n.client.readContract({ address: token, abi: ERC20_ABI, functionName: "decimals" }),
      n.client.readContract({ address: token, abi: ERC20_ABI, functionName: "symbol" }),
    ])) as [number, string];
    const meta = { decimals: Number(decimals), symbol };
    metaCache.set(n.name, meta);
    return meta;
  }
  /** Per-token NFT metadata URIs for a series; undefined when the chain has no NFT deployed. */
  async function seriesMetadata(
    n: Network,
    series: Hex,
  ): Promise<{ collection: string; issued: string; settled: string } | undefined> {
    try {
      const nft = addr(n, "nft");
      const [issuedId, settledId] = (await n.client.readContract({
        address: nft,
        abi: NFT_ABI,
        functionName: "tokenIds",
        args: [series],
      })) as [bigint, bigint];
      const [collection, issued, settled] = (await Promise.all([
        n.client.readContract({ address: nft, abi: NFT_ABI, functionName: "contractURI" }),
        n.client.readContract({ address: nft, abi: NFT_ABI, functionName: "uri", args: [issuedId] }),
        n.client.readContract({ address: nft, abi: NFT_ABI, functionName: "uri", args: [settledId] }),
      ])) as [string, string, string];
      return { collection, issued, settled };
    } catch {
      return undefined;
    }
  }
  /**
   * Payment tokens a series accepts: the vault router's assets for either of its
   * currencies. An issuance-currency token only settles while both rudis rates are
   * published and fresh, which `quoteSettlement` is the one to answer.
   */
  async function settlementTokens(n: Network, series: Hex): Promise<`0x${string}`[]> {
    const d = (await n.client.readContract({
      address: addr(n, "intex"),
      abi: INTEX_ABI,
      functionName: "seriesData",
      args: [series],
    })) as { referenceCurrency: number; issuanceCurrency: number };
    const currencies = [d.referenceCurrency];
    if (d.issuanceCurrency !== d.referenceCurrency) currencies.push(d.issuanceCurrency);
    const perCurrency = await Promise.all(
      currencies.map(
        (iso) =>
          n.client.readContract({
            address: addr(n, "vaultRouter"),
            abi: VAULT_ROUTER_ABI,
            functionName: "referenceCurrencyAssets",
            args: [iso],
          }) as Promise<readonly `0x${string}`[]>,
      ),
    );
    const seen = new Set<`0x${string}`>();
    for (const asset of perCurrency.flat()) seen.add(getAddress(asset));
    return [...seen];
  }

  /**
   * What settling one Intex of `series` with `token` costs, in that token's minor
   * units, and the ISO 4217 code the payment is denominated in.
   */
  async function quoteSettlement(
    n: Network,
    series: Hex,
    token: `0x${string}`,
  ): Promise<{ settlementCurrency: number; payableUnits: bigint }> {
    const [settlementCurrency, payableUnits] = (await n.client.readContract({
      address: addr(n, "factory"),
      abi: FACTORY_ABI,
      functionName: "quoteSettlement",
      args: [series, token],
    })) as [number, bigint];
    return { settlementCurrency: Number(settlementCurrency), payableUnits };
  }

  /** Bid rate as a fraction of strike ("0.8" = 80%) to the uint32 1e6 fixed-point the contract expects. */
  function toBidRate(rate: string): bigint {
    const raw = parseUnits(rate, 6);
    if (raw < 0n || raw > SCALE_1E6) throw new Error(`bid rate ${rate} must be 0..1 (0-100% of strike)`);
    return raw;
  }

  // --- shared argument schemas ---
  const networkArg = z.string().describe(`network name (one of: ${NETWORKS.map((d) => d.name).join(", ")})`);
  const accountArg = z.string().optional().describe("0x address to query (default: the configured signer)");
  const seriesArg = z
    .string()
    .describe('series id, e.g. "20260212-TRY-U"')
    .transform((v) => toSeriesId(v));
  const worldwideDayArg = z.number().int().describe("auction worldwide day (yyyymmdd)");
  const quantityArg = z.number().int().describe("bid quantity (uint16)");
  const rateArg = z
    .string()
    .describe('bid rate as a fraction of strike, 0..1 (e.g. "0.8" = 80% of strike; min from auction_info)');
  const issuanceCurrencyArg = z
    .number()
    .int()
    .describe("declared issuance currency, ISO 4217 numeric (e.g. 949 = TRY); any 1..999 code");
  const referenceCurrencyArg = z
    .number()
    .int()
    .describe("reference currency the bid prices in, ISO 4217 numeric; must be one the day prices (auction_info)");
  const amountArg = z.string().describe("amount as the raw on-chain integer");
  const recipientArg = z.string().optional().describe("recipient on Rehearsal Network (default: the signer)");
  const waitArg = z.boolean().optional().describe("wait for the receipt (default true)");

  // --- Series ledger (outbe Intex) -----------------------------------
  server.tool(
    "intex_series_info",
    "Canonical series record from the Rudis Intex: promis load, entry/floor/call prices, currencies, " +
      "lifecycle state (Issued/Qualified/Called/Expired), issued/called timestamps, the derived " +
      "callDeadline/expired pair - check `expired` before attempting settle (past-deadline settles revert) - " +
      "and how the issued units split into settled, parked and still-outstanding.",
    { series: seriesArg, network: networkArg.optional() },
    handler(async ({ series, network }) => {
      const n = await resolveNetwork(network ?? "rudis-rehearsal");
      const d = (await n.client.readContract({
        address: addr(n, "intex"),
        abi: INTEX_ABI,
        functionName: "seriesData",
        args: [series],
      })) as Record<string, bigint | number>;
      const u256 = (v: bigint | number) => v as bigint;
      const callDeadlineSec = Number(d.calledAt) > 0 ? Number(d.calledAt) + Number(d.callNoticePeriod) : 0;
      const metadata = await seriesMetadata(n, series);
      return ok({
        network: n.name,
        seriesId: fromSeriesId(d.seriesId as unknown as Hex),
        // scales per crates/core/intex/src/schema.rs (SeriesRecord):
        promisLoad: { raw: d.promisLoadMinor.toString(), value: formatUnits(u256(d.promisLoadMinor), 6) },
        entryPrice: { raw: d.entryPriceMinor.toString(), value: formatUnits(u256(d.entryPriceMinor), 6), scale: "1e6 ISO stable-unit" },
        floorPrice: { raw: d.floorPriceMinor.toString(), value: formatUnits(u256(d.floorPriceMinor), 6), scale: "1e6 ISO stable-unit" },
        callPrice: { raw: d.callPriceMinor.toString(), value: formatUnits(u256(d.callPriceMinor), 6), scale: "1e6 ISO stable-unit" },
        issuedIntexCount: Number(d.issuedIntexCount),
        settledUnits: Number(d.settledUnits),
        parkedUnits: Number(d.parkedUnits),
        // Unrealized units lose their load to the pool when the call window closes.
        unrealizedUnits: Number(d.issuedIntexCount) - Number(d.settledUnits) - Number(d.parkedUnits),
        callWindow: Number(d.callWindow),
        callThreshold: Number(d.callThreshold),
        callNoticePeriod: Number(d.callNoticePeriod),
        issuanceCurrency: Number(d.issuanceCurrency), // ISO 4217 numeric
        referenceCurrency: Number(d.referenceCurrency),
        worldwideDay: Number(d.worldwideDay),
        state: intexState(d.state),
        issuedAt: epochIso(d.issuedAt),
        calledAt: epochIso(d.calledAt),
        callDeadline: epochIso(callDeadlineSec),
        expired: callDeadlineSec > 0 && Math.floor(Date.now() / 1000) > callDeadlineSec,
        metadata,
      });
    }),
  );

  server.tool(
    "intex_series_list",
    "Enumerate series ids that exist in the Rudis Intex (dense enumeration).",
    { network: networkArg.optional() },
    handler(async ({ network }) => {
      const n = await resolveNetwork(network ?? "rudis-rehearsal");
      const total = Number(
        (await n.client.readContract({
          address: addr(n, "intex"),
          abi: INTEX_ABI,
          functionName: "totalSeries",
        })) as bigint,
      );
      const ids: string[] = [];
      for (let i = 0; i < total; i++) {
        const id = (await n.client.readContract({
          address: addr(n, "intex"),
          abi: INTEX_ABI,
          functionName: "seriesAt",
          args: [BigInt(i)],
        })) as Hex;
        ids.push(fromSeriesId(id));
      }
      return ok({ network: n.name, total, seriesIds: ids });
    }),
  );

  // --- NFT holdings (BSC or outbe IntexNFT1155) ------------------------------
  server.tool(
    "intex_holdings_by_owner",
    "Intex NFT holdings for an address: owned token ids, balances, decoded status (Issued/Settled), and " +
      "for Issued ones the series lifecycle with its callDeadline. Defaults to bsc-testnet (where won NFTs " +
      "land); pass network to read Rehearsal Network. A holding away from Rehearsal Network cannot be settled where it sits - bridge " +
      "it over with intex_bridge_send before the deadline shown here.",
    { account: accountArg, network: networkArg.optional() },
    handler(async ({ account, network }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      const who = whoever(account);
      const [tokenIds, balances] = (await n.client.readContract({
        address: addr(n, "nft"),
        abi: NFT_ABI,
        functionName: "getOwnedSeriesWithBalances",
        args: [who],
      })) as [bigint[], bigint[]];
      const holdings = await Promise.all(
        tokenIds.map(async (tokenId, i) => {
          const status = (await n.client.readContract({
            address: addr(n, "nft"),
            abi: NFT_ABI,
            functionName: "statusOf",
            args: [tokenId],
          })) as number;
          const base = { tokenId: tokenId.toString(), balance: balances[i].toString(), status: intexStatus(status) };
          // An Issued token id is the series id itself, so the lifecycle is one read away. A Settled id is
          // hashed and carries no deadline - that position is already settled.
          if (base.status.name !== "Issued") return base;
          const seriesHex = `0x${tokenId.toString(16).padStart(28, "0")}` as Hex;
          try {
            const d = (await n.client.readContract({
              address: addr(n, "nft"),
              abi: NFT_ABI,
              functionName: "readData",
              args: [seriesHex],
            })) as { state: number; calledAt: bigint | number; callTrigger: { callNoticePeriod: bigint | number } };
            const deadlineSec =
              Number(d.calledAt) > 0 ? Number(d.calledAt) + Number(d.callTrigger.callNoticePeriod) : 0;
            return {
              ...base,
              series: fromSeriesId(seriesHex),
              state: intexState(d.state),
              callDeadline: epochIso(deadlineSec),
              expired: deadlineSec > 0 && Math.floor(Date.now() / 1000) > deadlineSec,
            };
          } catch {
            // A series the chain does not know is still a holding worth listing.
            return base;
          }
        }),
      );
      return ok({ network: n.name, account: who, count: holdings.length, holdings });
    }),
  );

  server.tool(
    "intex_series_balance",
    "An address's Intex NFT balance for one series, split into issued and settled token ids. Reads the " +
      "chain you ask for; settlement only happens on Rehearsal Network, so an issued balance found elsewhere has to be " +
      "bridged over before the series callDeadline (intex_series_info shows it).",
    { series: seriesArg, account: accountArg, network: networkArg.optional() },
    handler(async ({ series, account, network }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      const who = whoever(account);
      const [issued, settled] = (await n.client.readContract({
        address: addr(n, "nft"),
        abi: NFT_ABI,
        functionName: "tokenIds",
        args: [series],
      })) as [bigint, bigint];
      const [issuedBal, settledBal] = (await Promise.all([
        n.client.readContract({ address: addr(n, "nft"), abi: NFT_ABI, functionName: "balanceOf", args: [who, issued] }),
        n.client.readContract({ address: addr(n, "nft"), abi: NFT_ABI, functionName: "balanceOf", args: [who, settled] }),
      ])) as [bigint, bigint];
      return ok({
        network: n.name,
        series,
        account: who,
        issued: { tokenId: issued.toString(), balance: issuedBal.toString() },
        settled: { tokenId: settled.toString(), balance: settledBal.toString() },
      });
    }),
  );

  // --- Auctions (BSC IntexAuction) -------------------------------------------
  const auctionStageOf = (n: Network, worldwideDay: number) =>
    n.client.readContract({
      address: addr(n, "auction"),
      abi: AUCTION_ABI,
      functionName: "getAuctionStage",
      args: [worldwideDay],
    }) as Promise<number>;

  /** Probe getAuctionStage across a yyyymmdd date window; drop dates with no auction. */
  async function discoverByDate(n: Network, fromDate: number, toDate: number): Promise<{ worldwideDay: number; stage: number }[]> {
    const probed = await Promise.all(
      ymdRange(fromDate, toDate).map(async (worldwideDay) => {
        try {
          return { worldwideDay, stage: await auctionStageOf(n, worldwideDay) };
        } catch {
          return null; // getAuctionStage reverts AuctionNotFound for empty dates
        }
      }),
    );
    return probed.filter((x): x is { worldwideDay: number; stage: number } => x !== null);
  }

  server.tool(
    "auctions_active",
    "Active Intex auctions and their stage. Auction ids are worldwide days (yyyymmdd); probes a date window " +
      "(default today-30..+2, override via from_date/to_date). Active = CommittingBids or RevealingBids; " +
      "pass include_all for every stage.",
    {
      network: networkArg.optional(),
      include_all: z.boolean().optional(),
      from_date: z.number().int().optional().describe("window start yyyymmdd (default today-30)"),
      to_date: z.number().int().optional().describe("window end yyyymmdd (default today+2)"),
    },
    handler(async ({ network, include_all, from_date, to_date }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      const today = todayYmd();
      const from = from_date ?? ymdShift(today, -DEFAULT_DAYS_BACK);
      const to = to_date ?? ymdShift(today, DEFAULT_DAYS_AHEAD);
      const probed = await discoverByDate(n, from, to);
      const auctions = probed.map((p) => ({ worldwideDay: p.worldwideDay, stage: auctionStage(p.stage) }));
      const filtered = include_all ? auctions : auctions.filter((au) => isActiveStage(au.stage.code));
      return ok({ network: n.name, window: { from, to }, count: filtered.length, auctions: filtered });
    }),
  );

  server.tool(
    "auction_info",
    "One auction's stage, schedule (commit/reveal/issuance ends in UTC), and params (promis-load strike, " +
      "min bid rate/quantity, and one entry/floor/call row per currency the day prices - bid in one of those). " +
      "Bids are sealed: the bid counts and clearing result stay 0 until clearing runs after reveal, so 0 here " +
      "does NOT mean there are no participants.",
    { worldwideDay: worldwideDayArg, network: networkArg.optional() },
    handler(async ({ worldwideDay, network }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      const [stage, info, meta] = await Promise.all([
        auctionStageOf(n, worldwideDay),
        n.client.readContract({ address: addr(n, "auction"), abi: AUCTION_ABI, functionName: "getAuctionInfo", args: [worldwideDay] }),
        paymentMeta(n),
      ]);
      const dec = meta.decimals;
      const d = info as {
        worldwideDayState: number;
        schedule: { commitEnd: number; revealEnd: number; issuanceEnd: number };
        params: {
          promisLoadMinor: bigint;
          callTrigger: { callWindow: number; callThreshold: number; callNoticePeriod: number };
          minIntexBidRate: bigint;
          minIntexBidQuantity: number;
          prices: readonly {
            isoCode: number;
            entryPriceMinor: bigint;
            floorPriceMinor: bigint;
            callPriceMinor: bigint;
          }[];
          commitBondMinor: bigint;
        };
        result: { auctionClearingRate: bigint; wonBidsCount: number; issuedIntexCount: number; issuedIntexLoadedPromis: bigint };
      };
      return ok({
        network: n.name,
        worldwideDay,
        stage: auctionStage(stage),
        worldwideDayState: d.worldwideDayState,
        schedule: {
          commitEnd: epochIso(d.schedule.commitEnd),
          revealEnd: epochIso(d.schedule.revealEnd),
          issuanceEnd: epochIso(d.schedule.issuanceEnd),
        },
        paymentToken: { symbol: meta.symbol, decimals: dec },
        params: {
          // Protocol-6 per-Intex PROMIS load. Escrow converts the calculated lock to wrudis-18.
          promisLoadMinor: {
            raw: d.params.promisLoadMinor.toString(),
            value: formatUnits(d.params.promisLoadMinor, 6),
            scale: "1e6 PROMIS protocol units",
          },
          callTrigger: {
            callWindow: d.params.callTrigger.callWindow,
            callThreshold: d.params.callTrigger.callThreshold,
            callNoticePeriod: d.params.callTrigger.callNoticePeriod,
          },
          // bid rates are 1e6 fixed-point (fraction of strike).
          minIntexBidRate: { raw: d.params.minIntexBidRate.toString(), value: formatUnits(d.params.minIntexBidRate, 6) },
          minIntexBidQuantity: Number(d.params.minIntexBidQuantity),
          // entry bond pulled at commit and returned at reveal/cancel; 0 = no bond.
          commitBondMinor: { raw: d.params.commitBondMinor.toString(), value: formatUnits(d.params.commitBondMinor, dec) },
          // A bid's reference currency must appear here.
          prices: d.params.prices.map((row) => ({
            isoCode: Number(row.isoCode),
            entryPrice: priced(row.entryPriceMinor),
            floorPrice: priced(row.floorPriceMinor),
            callPrice: priced(row.callPriceMinor),
          })),
        },
        result: {
          note: "populated only after clearing",
          auctionClearingRate: { raw: d.result.auctionClearingRate.toString(), value: formatUnits(d.result.auctionClearingRate, 6) },
          wonBidsCount: Number(d.result.wonBidsCount),
          issuedIntexCount: Number(d.result.issuedIntexCount),
          issuedIntexLoadedPromis: d.result.issuedIntexLoadedPromis.toString(),
        },
      });
    }),
  );

  server.tool(
    "auction_chains",
    "Per-chain bid fan-in for one auction day, read from Rehearsal Network: the day's target-chain snapshot and, for " +
      "each chain, whether its bids arrived in full (BIDS_DONE) and how many. Clearing runs once every " +
      "chain reports or the fan-in deadline passes; a chain still done=false after clearing was skipped " +
      "and its bidders reclaim locally (see auction_bids_by_owner on that chain).",
    { worldwideDay: worldwideDayArg, network: networkArg.optional() },
    handler(async ({ worldwideDay, network }) => {
      const n = await resolveNetwork(network ?? "rudis-rehearsal");
      const desis = addr(n, "desis");
      const chains = (await n.client.readContract({
        address: addr(n, "originRouter"),
        abi: ORIGIN_ROUTER_ABI,
        functionName: "targetsOf",
        args: [worldwideDay],
      })) as number[];
      const [stage, total] = (await Promise.all([
        n.client.readContract({ address: desis, abi: DESIS_ABI, functionName: "getAuctionStage", args: [worldwideDay] }),
        n.client.readContract({ address: desis, abi: DESIS_ABI, functionName: "getBidsCount", args: [worldwideDay] }),
      ])) as [number, bigint];
      const perChain = await Promise.all(
        chains.map(async (chainId) => {
          const [done, bids] = (await Promise.all([
            n.client.readContract({ address: desis, abi: DESIS_ABI, functionName: "isChainDone", args: [worldwideDay, chainId] }),
            n.client.readContract({ address: desis, abi: DESIS_ABI, functionName: "getChainBidsCount", args: [worldwideDay, chainId] }),
          ])) as [boolean, bigint];
          return { chainId, done, bids: Number(bids) };
        }),
      );
      return ok({
        network: n.name,
        worldwideDay,
        stage: desisStage(stage),
        totalBids: Number(total),
        chains: perChain,
      });
    }),
  );

  server.tool(
    "auction_bids_by_owner",
    "Your commit/reveal status across active auctions, plus your escrow money on that chain: the commit " +
      "bond (held from commit until reveal/cancel) and the bid lock (held from reveal until finalization). " +
      "Emits a hint when funds are stuck - a no-reveal bond reclaimable via intex_claim_commit_bond, or a " +
      "never-finalized lock (e.g. the chain missed the clearing deadline) reclaimable in full via " +
      "auction_claim_refund after the shown refundClaimableAt. Pass worldwideDay to check just one.",
    { account: accountArg, worldwideDay: worldwideDayArg.optional(), network: networkArg.optional() },
    handler(async ({ account, worldwideDay, network }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      const who = whoever(account);
      let targets: number[];
      if (worldwideDay !== undefined) {
        targets = [worldwideDay];
      } else {
        const today = todayYmd();
        const probed = await discoverByDate(n, ymdShift(today, -DEFAULT_DAYS_BACK), ymdShift(today, DEFAULT_DAYS_AHEAD));
        targets = probed.filter((x) => isActiveStage(x.stage)).map((x) => x.worldwideDay).sort((x, y) => x - y);
      }
      const refundDelay = Number(
        (await n.client.readContract({ address: addr(n, "escrow"), abi: ESCROW_ABI, functionName: "UNFINALIZED_REFUND_DELAY" })) as number,
      );
      const bids = await Promise.all(
        targets.map(async (wwd) => {
          const [commitHash, revealed, lock, bond] = (await Promise.all([
            n.client.readContract({ address: addr(n, "auction"), abi: AUCTION_ABI, functionName: "committedBidsByHash", args: [wwd, who] }),
            n.client.readContract({ address: addr(n, "auction"), abi: AUCTION_ABI, functionName: "revealedBidsByBidder", args: [wwd, who] }),
            n.client.readContract({ address: addr(n, "escrow"), abi: ESCROW_ABI, functionName: "getBidLock", args: [wwd, who] }),
            n.client.readContract({ address: addr(n, "escrow"), abi: ESCROW_ABI, functionName: "getCommitBond", args: [wwd, who] }),
          ])) as [
            Hex,
            boolean,
            { lockedAmount: bigint; lockedAt: number; status: number; failedRefund: bigint; splitRecorded: boolean },
            { amount: bigint; lockedAt: number },
          ];
          const committed = commitHash !== "0x" && /[1-9a-f]/i.test(commitHash.slice(2));
          const stage = await auctionStageOf(n, wwd);
          const out: Record<string, unknown> = { worldwideDay: wwd, committed, revealed, stage: auctionStage(stage) };
          const hints: string[] = [];
          if (bond.amount > 0n) {
            out.commitBond = { amount: bond.amount.toString(), lockedAt: epochIso(bond.lockedAt) };
            // A held bond during commit/reveal is normal (it returns at reveal/cancel); past
            // that window a no-reveal commit left it behind.
            if (!revealed && !isActiveStage(stage)) {
              hints.push(
                "entry bond left by a no-reveal commit; reclaim via intex_claim_commit_bond (immediately on a cancelled day, else 24 hours past revealEnd)",
              );
            }
          }
          if (lock.status !== 0) {
            const [, , , finalized] = (await n.client.readContract({
              address: addr(n, "escrow"),
              abi: ESCROW_ABI,
              functionName: "auctionEscrowState",
              args: [wwd],
            })) as [bigint, number, number, boolean];
            const escrow: Record<string, unknown> = {
              lockedAmount: lock.lockedAmount.toString(),
              status: lockStatus(lock.status),
              finalized,
            };
            // Locked + never finalized = no refund instructions reached this chain; the bidder
            // self-serves the full principal once the delay passes. Only then is the claim time
            // meaningful - a finalized lock refunds through the normal path, not this one.
            if (lock.status === 1 && !finalized) {
              escrow.refundClaimableAt = epochIso(lock.lockedAt + refundDelay);
              hints.push(
                "escrow not finalized on this chain; if no refund arrives, claim the full lock via auction_claim_refund from refundClaimableAt",
              );
            }
            out.escrow = escrow;
          }
          if (hints.length > 0) out.hints = hints;
          return out as { worldwideDay: number; committed: boolean; revealed: boolean };
        }),
      );
      const mine = bids.filter((b) => b.committed || b.revealed);
      return ok({ network: n.name, bidder: who, count: mine.length, bids: worldwideDay !== undefined ? bids : mine });
    }),
  );

  // --- Bid commit / reveal (BSC IntexAuction, signed) ------------------------
  async function signReveal(
    n: Network,
    account: Account,
    worldwideDay: number,
    quantity: number,
    bidRate: bigint,
    issuanceCurrency: number,
    referenceCurrency: number,
  ): Promise<Hex> {
    const typedData = revealBidTypedData({
      chainId: n.chainId,
      verifyingContract: addr(n, "auction"),
      worldwideDay,
      bidder: account.address,
      quantity,
      bidRate: Number(bidRate),
      issuanceCurrency,
      referenceCurrency,
    });
    if (!account.signTypedData) throw new Error("the configured account cannot sign typed data");
    return account.signTypedData(typedData);
  }

  server.tool(
    "auction_bid_commit",
    "Commit a sealed Intex bid: signs the EIP-712 RevealBid and submits keccak256(signature) as the commit " +
      "hash (no separate salt). When the auction carries an entry bond (commitBondMinor > 0), commitBid pulls " +
      "it into escrow in the same transaction - the tool auto-approves the escrow if the allowance is short. " +
      "The bond returns at reveal/cancel; a green-day no-reveal locks it for 24 hours past revealEnd " +
      "(intex_claim_commit_bond). IMPORTANT: save your (worldwideDay, quantity, rate, currencies); you must repeat " +
      "them to reveal, they can't be recovered on-chain, and are only remembered this session. Requires OUTBE_PRIVATE_KEY.",
    {
      worldwideDay: worldwideDayArg,
      quantity: quantityArg,
      rate: rateArg,
      issuanceCurrency: issuanceCurrencyArg,
      referenceCurrency: referenceCurrencyArg,
      network: networkArg.optional(),
      wait: waitArg,
    },
    handler(async ({ worldwideDay, quantity, rate, issuanceCurrency, referenceCurrency, network, wait }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      const account = requireAccount();
      const bidRate = toBidRate(rate);

      // Entry bond: the escrow pulls it inside commitBid, so cover the allowance up front.
      const info = (await n.client.readContract({
        address: addr(n, "auction"),
        abi: AUCTION_ABI,
        functionName: "getAuctionInfo",
        args: [worldwideDay],
      })) as { params: { commitBondMinor: bigint } };
      const bond = info.params.commitBondMinor;
      let autoApprove: { txHash: Hex; amount: string } | null = null;
      let note = "No entry bond on this worldwideDay; nothing is locked at commit.";
      if (bond > 0n) {
        const { decimals: dec, symbol } = await paymentMeta(n);
        const bondHuman = formatUnits(bond, dec);
        const token = addr(n, "paymentToken");
        const escrow = addr(n, "escrow");
        const allowance = (await n.client.readContract({
          address: token,
          abi: ERC20_ABI,
          functionName: "allowance",
          args: [account.address, escrow],
        })) as bigint;
        if (allowance < bond) {
          const approveData = encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [escrow, bond] });
          const ar = await submit(n, token, approveData, 0n, true); // must be mined before commit
          autoApprove = { txHash: ar.txHash, amount: bond.toString() };
        }
        note =
          `Commit locks a ${bondHuman} ${symbol} entry bond in escrow; it returns at reveal/cancel. ` +
          `A green-day no-reveal keeps it locked until 24 hours past revealEnd (intex_claim_commit_bond).`;
      }

      const signature = await signReveal(
        n,
        account,
        worldwideDay,
        quantity,
        bidRate,
        issuanceCurrency,
        referenceCurrency,
      );
      const hash = commitHash(signature);
      const data = encodeFunctionData({ abi: AUCTION_ABI, functionName: "commitBid", args: [worldwideDay, hash] });
      const receipt = await submit(n, addr(n, "auction"), data, 0n, wait);
      return ok({
        network: n.name,
        worldwideDay,
        quantity,
        rate,
        bidRate: bidRate.toString(),
        issuanceCurrency,
        referenceCurrency,
        commitHash: hash,
        bond: bond.toString(),
        autoApprove,
        note,
        ...receipt,
        reminder:
          `Record worldwideDay=${worldwideDay}, quantity=${quantity}, rate=${rate} - required to reveal, ` +
          `not recoverable on-chain, remembered only this session.`,
      });
    }),
  );

  server.tool(
    "auction_bid_reveal",
    "Reveal a committed Intex bid: re-derives the same signature from (worldwideDay, quantity, rate, currencies) " +
    "and submits revealBid; the escrow calculates quantity * protocol-6 PROMIS load * rate / 1e6, then converts " +
      "that result by 1e12 into native-18 wrudis for the lock. The reference currency must be one the day prices, the issuance currency any " +
      "1..999 code. Auto-approves the escrow first if the allowance is short. Requires OUTBE_PRIVATE_KEY.",
    {
      worldwideDay: worldwideDayArg,
      quantity: quantityArg,
      rate: rateArg,
      issuanceCurrency: issuanceCurrencyArg,
      referenceCurrency: referenceCurrencyArg,
      network: networkArg.optional(),
      wait: waitArg,
    },
    handler(async ({ worldwideDay, quantity, rate, issuanceCurrency, referenceCurrency, network, wait }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      const account = requireAccount();
      const { decimals: dec, symbol } = await paymentMeta(n);
      const bidRate = toBidRate(rate);

      // Calculate in protocol-6 from the per-Intex PROMIS load and 1e6 rate,
      // then convert exactly once to native-18 wrudis for the escrow boundary.
      const info = (await n.client.readContract({
        address: addr(n, "auction"),
        abi: AUCTION_ABI,
        functionName: "getAuctionInfo",
        args: [worldwideDay],
      })) as { params: { promisLoadMinor: bigint; commitBondMinor: bigint } };
      const strike = info.params.promisLoadMinor;
      const lockAmount = wcoenLockAmount(BigInt(quantity), strike, bidRate);
      const lockHuman = formatUnits(lockAmount, dec);
      const token = addr(n, "paymentToken");
      const escrow = addr(n, "escrow");
      const allowance = (await n.client.readContract({
        address: token,
        abi: ERC20_ABI,
        functionName: "allowance",
        args: [account.address, escrow],
      })) as bigint;
      let autoApprove: { txHash: Hex; amount: string } | null = null;
      let note: string;
      if (allowance < lockAmount) {
        const approveData = encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [escrow, lockAmount] });
        const ar = await submit(n, token, approveData, 0n, true); // must be mined before reveal
        autoApprove = { txHash: ar.txHash, amount: lockAmount.toString() };
        note = `Reveal locks ${lockHuman} ${symbol} (${quantity} x strike x ${rate}) in escrow. Allowance was short, so the escrow was approved for ${lockHuman} ${symbol} first, then the bid was revealed.`;
      } else {
        note = `Reveal locks ${lockHuman} ${symbol} (${quantity} x strike x ${rate}) in escrow; allowance already covered it, no approval needed.`;
      }
      if (info.params.commitBondMinor > 0n) {
        note += ` The ${formatUnits(info.params.commitBondMinor, dec)} ${symbol} entry bond returns within the same transaction (released before the bid lock, so it can fund the bid).`;
      }

      const signature = await signReveal(
        n,
        account,
        worldwideDay,
        quantity,
        bidRate,
        issuanceCurrency,
        referenceCurrency,
      );
      const data = encodeFunctionData({
        abi: AUCTION_ABI,
        functionName: "revealBid",
        args: [
          worldwideDay,
          quantity,
          bidRate,
          issuanceCurrency,
          referenceCurrency,
          BigInt(n.chainId),
          signature,
        ],
      });
      const receipt = await submit(n, addr(n, "auction"), data, 0n, wait);
      return ok({ network: n.name, worldwideDay, quantity, rate, bidRate: bidRate.toString(), locked: lockHuman, autoApprove, note, ...receipt });
    }),
  );

  server.tool(
    "auction_bid_cancel",
    "Cancel a committed bid for a worldwide day before the reveal stage. Requires OUTBE_PRIVATE_KEY.",
    { worldwideDay: worldwideDayArg, network: networkArg.optional(), wait: waitArg },
    handler(async ({ worldwideDay, network, wait }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      requireAccount();
      const data = encodeFunctionData({ abi: AUCTION_ABI, functionName: "cancelCommit", args: [worldwideDay] });
      const receipt = await submit(n, addr(n, "auction"), data, 0n, wait);
      return ok({ network: n.name, worldwideDay, ...receipt });
    }),
  );

  server.tool(
    "intex_claim_commit_bond",
    "Reclaim an entry bond left behind by a no-reveal commit. Permissionless and always pays the stored " +
      "bidder: a cancelled (red-day) auction releases immediately, otherwise the bond is claimable only " +
      "24 hours past revealEnd. Requires OUTBE_PRIVATE_KEY.",
    { worldwideDay: worldwideDayArg, bidder: accountArg, network: networkArg.optional(), wait: waitArg },
    handler(async ({ worldwideDay, bidder, network, wait }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      const account = requireAccount();
      const who = bidder ? getAddress(bidder) : account.address;
      const data = encodeFunctionData({ abi: AUCTION_ABI, functionName: "claimCommitBond", args: [worldwideDay, who] });
      const receipt = await submit(n, addr(n, "auction"), data, 0n, wait);
      return ok({ network: n.name, worldwideDay, bidder: who, ...receipt });
    }),
  );

  server.tool(
    "auction_claim_refund",
    "Reclaim a bid lock the finalization never covered: the full principal 72h after the lock when no " +
      "refund instructions reached this chain (e.g. it missed the clearing deadline), or the recorded " +
      "refund portion post-finalize. Permissionless and always pays the stored bidder. Requires OUTBE_PRIVATE_KEY.",
    { worldwideDay: worldwideDayArg, bidder: accountArg, network: networkArg.optional(), wait: waitArg },
    handler(async ({ worldwideDay, bidder, network, wait }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      const account = requireAccount();
      const who = bidder ? getAddress(bidder) : account.address;
      const data = encodeFunctionData({ abi: ESCROW_ABI, functionName: "claimRefund", args: [worldwideDay, who] });
      const receipt = await submit(n, addr(n, "escrow"), data, 0n, wait);
      return ok({ network: n.name, worldwideDay, bidder: who, ...receipt });
    }),
  );

  // --- Bid funding (BSC payment token -> EscrowAdapter) ----------------------
  server.tool(
    "intex_payment_allowance",
    "Payment-token allowance granted to the EscrowAdapter and the account's balance, with token decimals/symbol.",
    { account: accountArg, network: networkArg.optional() },
    handler(async ({ account, network }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      const who = whoever(account);
      const token = addr(n, "paymentToken");
      const escrow = addr(n, "escrow");
      const [allowance, balance, decimals, symbol] = (await Promise.all([
        n.client.readContract({ address: token, abi: ERC20_ABI, functionName: "allowance", args: [who, escrow] }),
        n.client.readContract({ address: token, abi: ERC20_ABI, functionName: "balanceOf", args: [who] }),
        n.client.readContract({ address: token, abi: ERC20_ABI, functionName: "decimals" }),
        n.client.readContract({ address: token, abi: ERC20_ABI, functionName: "symbol" }),
      ])) as [bigint, bigint, number, string];
      const d = Number(decimals);
      return ok({
        network: n.name,
        account: who,
        token: { address: token, symbol, decimals: d },
        escrow,
        allowance: { raw: allowance.toString(), value: formatUnits(allowance, d) },
        balance: { raw: balance.toString(), value: formatUnits(balance, d) },
      });
    }),
  );

  server.tool(
    "intex_payment_approve",
    "Manually approve the EscrowAdapter to pull the payment token. Usually unnecessary - auction_bid_reveal " +
      "auto-approves what it needs. Pass amount in token units (e.g. \"100\") or max=true. Requires OUTBE_PRIVATE_KEY.",
    {
      amount: z.string().optional().describe('token amount to approve, e.g. "100"'),
      max: z.boolean().optional().describe("approve the maximum instead of a fixed amount"),
      network: networkArg.optional(),
      wait: waitArg,
    },
    handler(async ({ amount, max, network, wait }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      requireAccount();
      if (!max && amount === undefined) throw new Error('pass amount (e.g. "100") or max=true');
      const value = max ? maxUint256 : parseUnits(amount as string, (await paymentMeta(n)).decimals);
      const token = addr(n, "paymentToken");
      const escrow = addr(n, "escrow");
      const data = encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [escrow, value] });
      const receipt = await submit(n, token, data, 0n, wait);
      return ok({ network: n.name, token, escrow, approved: max ? "max" : (amount as string), ...receipt });
    }),
  );

  // --- Bridge BSC -> outbe (IntexNFT1155Bridge, signed) ----------------------

  async function buildSendParam(n: Network, series: Hex, amount: bigint, recipient: Address) {
    const ids = (await n.client.readContract({
      address: addr(n, "nft"),
      abi: NFT_ABI,
      functionName: "tokenIds",
      args: [series],
    })) as [bigint, bigint];
    return {
      dstChainId: bridgeDstChainId(n.name),
      to: pad(recipient, { size: 32 }),
      tokenId: ids[0], // issued token id
      amount,
    };
  }


  server.tool(
    "intex_bridge_quote",
    "Bridge native fee to move an Intex NFT from BSC to Rehearsal Network. Bridging is holder-initiated at every stage: " +
      "to any recipient while the series is Issued or Qualified, and to yourself only once it is Called, up to " +
      "its callDeadline (read it with intex_series_info).",
    { series: seriesArg, amount: amountArg, recipient: recipientArg, network: networkArg.optional() },
    handler(async ({ series, amount, recipient, network }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      const to = recipient ? getAddress(recipient) : whoever();
      const sp = await buildSendParam(n, series, BigInt(amount), to);
      const fee = (await n.client.readContract({
        address: addr(n, "nftBridge"),
        abi: NFT_BRIDGE_ABI,
        functionName: "quoteSend",
        args: [sp],
      })) as bigint;
      return ok({
        network: n.name,
        series,
        tokenId: sp.tokenId.toString(),
        dstChainId: sp.dstChainId,
        recipient: to,
        fee: { nativeFee: { raw: fee.toString(), value: formatNativeAmount(n.chain, fee) } },
      });
    }),
  );

  server.tool(
    "intex_bridge_send",
    "Bridge an Intex NFT from BSC to Rehearsal Network, where settlement happens - nothing moves it for you, so a " +
      "position left on BSC past the series callDeadline can no longer be settled at all. Works at every " +
      "stage: to any recipient while Issued or Qualified, and to yourself only once the series is Called " +
      "(ownership is frozen then, so a recipient other than you is refused). The bridge burns your token " +
      "directly (role-gated), so no approval is needed. Auto-quotes the native fee (paid as value), which " +
      "you pay in the source chain's native token. Requires OUTBE_PRIVATE_KEY.",
    { series: seriesArg, amount: amountArg, recipient: recipientArg, network: networkArg.optional(), wait: waitArg },
    handler(async ({ series, amount, recipient, network, wait }) => {
      const n = await resolveNetwork(network ?? "bsc-testnet");
      const account = requireAccount();
      const bridge = addr(n, "nftBridge");
      const to = recipient ? getAddress(recipient) : account.address;
      const sp = await buildSendParam(n, series, BigInt(amount), to);
      const fee = (await n.client.readContract({
        address: bridge,
        abi: NFT_BRIDGE_ABI,
        functionName: "quoteSend",
        args: [sp],
      })) as bigint;
      const data = encodeFunctionData({ abi: NFT_BRIDGE_ABI, functionName: "send", args: [sp] });
      const receipt = await submit(n, bridge, data, fee, wait);
      return ok({
        network: n.name,
        series,
        tokenId: sp.tokenId.toString(),
        recipient: to,
        fee: { raw: fee.toString(), value: formatNativeAmount(n.chain, fee) },
        ...receipt,
      });
    }),
  );

  // --- Settlement + Promis (outbe IntexFactory, signed) ----------------------
  server.tool(
    "auction_bid_settle",
    "Settlement step 1: pay the strike and turn Issued Intexes into Settled (Promis is mined later via " +
      "intex_promis_mine). The cost is paid by spending a PayNote, so pass pay_note_proof: this call moves " +
      "no tokens of its own and needs no approval. Get the price with intex_settlement_tokens, deposit a " +
      "note of at least that size into IPayNote (from whichever wallet holds the money - a different one " +
      "keeps the two unlinked), then build the spend proof off-chain; the MCP cannot produce it. " +
      "Defaults to your own wallet; pass holder only if that holder authorized you via auction_settler_set. " +
      "Allowed when the series is Qualified (voluntary) or Called (forced, within the call period). The " +
      "Settled token (soulbound) and the later Promis go to the SIGNING wallet, not to holder; since the MCP " +
      "signs with one key, to land them on a different wallet that wallet must settle/mine itself. " +
      "Settlement only ever happens on Rehearsal Network: a position sitting on BSC has to be brought over with " +
      "intex_bridge_send first, and that has to land before the series callDeadline. Requires " +
      "OUTBE_PRIVATE_KEY.",
    {
      series: seriesArg,
      amount: amountArg,
      holder: accountArg,
      pay_note_proof: z.string().describe("0x-hex `outbe.paynote` spend proof naming the signing wallet as its spender"),
      network: networkArg.optional(),
      wait: waitArg,
    },
    handler(async ({ series, amount, holder, pay_note_proof, network, wait }) => {
      const n = await resolveNetwork(network ?? "rudis-rehearsal");
      const account = requireAccount();
      const intexHolder = holder ? getAddress(holder) : account.address;
      if (!/^0x[0-9a-fA-F]*$/.test(pay_note_proof) || pay_note_proof.length < 4) {
        throw new Error("pay_note_proof must be a 0x-prefixed hex PayNote spend proof");
      }

      const factory = addr(n, "factory");
      const data = encodeFunctionData({
        abi: FACTORY_ABI,
        functionName: "settle",
        args: [series, intexHolder, BigInt(amount), pay_note_proof as Hex],
      });
      const receipt = await submit(n, factory, data, 0n, wait);
      return ok({
        network: n.name,
        series,
        intexHolder,
        amount,
        self: intexHolder === account.address,
        ...receipt,
      });
    }),
  );

  server.tool(
    "intex_settlement_tokens",
    "Tokens you can settle a series with and the per-Intex cost in each. Use the cost to size the " +
      "PayNote you deposit before calling auction_bid_settle.",
    { series: seriesArg, network: networkArg.optional() },
    handler(async ({ series, network }) => {
      const n = await resolveNetwork(network ?? "rudis-rehearsal");
      const tokens = await settlementTokens(n, series);
      const priced = await Promise.all(
        tokens.map(async (token) => {
          const [decimals, symbol] = await Promise.all([
            n.client.readContract({ address: token, abi: ERC20_ABI, functionName: "decimals" }),
            n.client.readContract({ address: token, abi: ERC20_ABI, functionName: "symbol" }),
          ]);
          const base = { token, symbol: symbol as string, decimals: Number(decimals) };
          // A refused issuance-currency quote is this token's answer, not the list's.
          try {
            const { settlementCurrency, payableUnits } = await quoteSettlement(n, series, token);
            return {
              ...base,
              settlementCurrency,
              perUnit: { raw: payableUnits.toString(), value: formatUnits(payableUnits, Number(decimals)) },
            };
          } catch (error) {
            return { ...base, unavailable: (error as Error).message };
          }
        }),
      );
      return ok({ network: n.name, series, tokens: priced });
    }),
  );

  server.tool(
    "auction_settler_set",
    "Authorize another wallet to settle your position in a series. Call this from the holder wallet before " +
      "that wallet can settle on your behalf. Requires OUTBE_PRIVATE_KEY.",
    { series: seriesArg, settler: z.string().describe("0x address to authorize"), network: networkArg.optional(), wait: waitArg },
    handler(async ({ series, settler, network, wait }) => {
      const n = await resolveNetwork(network ?? "rudis-rehearsal");
      requireAccount();
      const data = encodeFunctionData({ abi: FACTORY_ABI, functionName: "setAuthorizedSettler", args: [series, getAddress(settler)] });
      const receipt = await submit(n, addr(n, "factory"), data, 0n, wait);
      return ok({ network: n.name, series, settler: getAddress(settler), ...receipt });
    }),
  );

  server.tool(
    "intex_promis_mine",
    "Settlement step 2: burn your Settled Intexes and mine Promis to your own wallet (run auction_bid_settle " +
      "first). The proof-of-work nonce is computed locally; you give only series and amount. Requires OUTBE_PRIVATE_KEY.",
    { series: seriesArg, amount: amountArg, network: networkArg.optional(), wait: waitArg },
    handler(async ({ series, amount, network, wait }) => {
      const n = await resolveNetwork(network ?? "rudis-rehearsal");
      const account = requireAccount();
      const holder = account.address;
      const amt = BigInt(amount);
      const sd = (await n.client.readContract({
        address: addr(n, "intex"),
        abi: INTEX_ABI,
        functionName: "seriesData",
        args: [series],
      })) as { promisLoadMinor: bigint };
      const promisAmount = sd.promisLoadMinor * amt;
      // seq = this holder's prior mines for the series (feeds the PoW preimage).
      const logs = await n.client.getLogs({
        address: addr(n, "factory"),
        event: PROMIS_MINED_EVENT,
        args: { seriesId: series, holder },
        fromBlock: 0n,
        toBlock: "latest",
      });
      const seq = logs.length;
      const pow = grindNonce(holder, promisAmount, series, seq);
      throw new Error(
        "minePromis also requires a Promis modify-auth mac and opNonce, which this server cannot produce: " +
          "the modify key is sealed to an ephemeral X25519 key by rudis_deriveKeys(Promis, ...) and no unsealing " +
          "or mac derivation is implemented here. " +
          `Proof of work is done - nonce ${pow.nonce} (seq ${seq}, difficulty ${POW_DIFFICULTY}, ` +
          `${pow.iterations} iterations, hash ${pow.hash}) ` +
          `for ${promisAmount} Promis on series ${series}. Submit minePromis(${series}, ${amt}, ${pow.nonce}, mac, opNonce) ` +
          "with a client that holds the modify key.",
      );
    }),
  );

  server.tool(
    "intex_promis_balance",
    "Promis balance for an address on Rehearsal Network.",
    { account: accountArg, network: networkArg.optional() },
    handler(async ({ account, network }) => {
      const n = await resolveNetwork(network ?? "rudis-rehearsal");
      const who = whoever(account);
      const bal = (await n.client.readContract({
        address: addr(n, "promis"),
        abi: ERC20_ABI,
        functionName: "balanceOf",
        args: [who],
      })) as bigint;
      return ok({ network: n.name, account: who, balance: { raw: bal.toString(), value: formatUnits(bal, 6) } });
    }),
  );
}
