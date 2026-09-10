import { task } from "hardhat/config";
import {
  createPublicClient,
  createWalletClient,
  getContract,
  http,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { getEnvRpcAndPk, makeChain } from "../../scripts/shared/chains.js";
import { getNetworkName } from "../../scripts/shared/taskUtils.js";
import { loadAbi } from "../../scripts/shared/abi.js";

type WireViem = {
  getContractAt: (name: string, address: `0x${string}`) => Promise<unknown>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getPublicClient: () => Promise<any>;
};

/** viem read/write facade for the wire network, built from its RPC + key, with ABIs from abi-export. */
async function getViemForWire(hre: unknown): Promise<WireViem> {
  const networkName = getNetworkName(hre);
  const { rpc, pk } = getEnvRpcAndPk(networkName);
  if (!pk) throw new Error(`Private key required for ${networkName}`);
  const chain = makeChain(networkName, rpc);
  const account = privateKeyToAccount(pk as `0x${string}`);
  const transport = http(rpc);
  const publicClient = createPublicClient({ chain, transport });
  const walletClient = createWalletClient({ account, chain, transport });
  return {
    getContractAt: async (name: string, address: `0x${string}`) =>
      getContract({ address, abi: loadAbi(name), client: { public: publicClient, wallet: walletClient } }),
    getPublicClient: async () => publicClient,
  };
}

/** Send a write tx and wait for its receipt before the next dependent call. */
async function sendAndWait(
  viem: WireViem,
  writeFn: () => Promise<`0x${string}`>,
): Promise<`0x${string}`> {
  const hash = await writeFn();
  const publicClient = await viem.getPublicClient();
  await publicClient.waitForTransactionReceipt({ hash });
  return hash;
}

interface AuctionWireArgs {
  intexAuctionContract: string;
  escrowContract: string;
}

interface EscrowWireArgs {
  escrowContract: string;
  intexAuctionContract: string;
  compactContract: string;
  paymentToken: string;
}

interface TargetBridgeWireArgs {
  bridgeContract: string;
  intexAuctionContract: string;
  intexContract: string;
  escrowContract: string;
}

interface OriginBridgeWireArgs {
  bridgeContract: string;
  desisContract: string;
  intexFactoryContract: string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const lazy = (fn: (args: any, hre: any) => Promise<void>) =>
  async () => ({ default: fn });

// ============================================================================
// Auction Wire
// ============================================================================

const auctionWireAction = async (args: AuctionWireArgs, hre: unknown) => {
  const viem = await getViemForWire(hre);
  
  console.log(`Wiring Auction...`);
  console.log(`  Auction: ${args.intexAuctionContract}`);
  console.log(`  Escrow: ${args.escrowContract}`);

  const auction = (await viem.getContractAt(
    "IntexAuction",
    args.intexAuctionContract as `0x${string}`
  )) as {
    read: {
      escrowContract: () => Promise<`0x${string}`>;
    };
    write: {
      wire: (args: [`0x${string}`]) => Promise<`0x${string}`>;
    };
  };

  const currentEscrow = await auction.read.escrowContract();

  if (currentEscrow !== "0x0000000000000000000000000000000000000000") {
    if (currentEscrow.toLowerCase() === args.escrowContract.toLowerCase()) {
      console.log(`[OK] Auction already wired to this Escrow`);
      return;
    }
    console.log(`[sync] Rewiring Auction (current: ${currentEscrow})`);
  }

  const txHash = await sendAndWait(viem, () =>
    auction.write.wire([args.escrowContract as `0x${string}`]),
  );
  console.log(`[OK] Auction wired. Tx: ${txHash}`);
};

const auctionWire = task("auction-wire", "Wire Auction to EscrowAdapter")
  .addOption({
    name: "intexAuctionContract",
    description: "Auction contract address",
    defaultValue: "",
  })
  .addOption({
    name: "escrowContract",
    description: "EscrowAdapter contract address",
    defaultValue: "",
  })
  .setAction(lazy(auctionWireAction));

// ============================================================================
// EscrowAdapter Wire
// ============================================================================

const escrowWireAction = async (args: EscrowWireArgs, hre: unknown) => {
  const viem = await getViemForWire(hre);
  
  console.log(`Wiring EscrowAdapter...`);
  console.log(`  Escrow: ${args.escrowContract}`);
  console.log(`  Auction: ${args.intexAuctionContract}`);
  console.log(`  Compact: ${args.compactContract}`);
  console.log(`  PaymentToken: ${args.paymentToken}`);

  const escrow = (await viem.getContractAt(
    "EscrowAdapter",
    args.escrowContract as `0x${string}`
  )) as {
    read: {
      intexAuctionContract: () => Promise<`0x${string}`>;
      compact: () => Promise<`0x${string}`>;
      paymentToken: () => Promise<`0x${string}`>;
    };
    write: {
      wire: (args: [`0x${string}`, `0x${string}`, `0x${string}`]) => Promise<`0x${string}`>;
    };
  };

  const [currentAuction, currentCompact, currentStable] = await Promise.all([
    escrow.read.intexAuctionContract(),
    escrow.read.compact(),
    escrow.read.paymentToken(),
  ]);

  const allMatch =
    currentAuction.toLowerCase() === args.intexAuctionContract.toLowerCase() &&
    currentCompact.toLowerCase() === args.compactContract.toLowerCase() &&
    currentStable.toLowerCase() === args.paymentToken.toLowerCase();

  if (allMatch) {
    console.log(`[OK] EscrowAdapter already wired to these contracts`);
    return;
  }

  if (currentAuction !== "0x0000000000000000000000000000000000000000") {
    const changed = [
      currentAuction.toLowerCase() !== args.intexAuctionContract.toLowerCase() && "auction",
      currentCompact.toLowerCase() !== args.compactContract.toLowerCase() && "compact",
      currentStable.toLowerCase() !== args.paymentToken.toLowerCase() && "paymentToken",
    ].filter(Boolean);
    console.log(`[sync] Rewiring EscrowAdapter (changed: ${changed.join(", ")})`);
  }

  const txHash = await sendAndWait(viem, () =>
    escrow.write.wire([
      args.intexAuctionContract as `0x${string}`,
      args.compactContract as `0x${string}`,
      args.paymentToken as `0x${string}`,
    ]),
  );
  console.log(`[OK] EscrowAdapter wired. Tx: ${txHash}`);
};

const escrowWire = task("escrow-wire", "Wire EscrowAdapter to Auction and external contracts")
  .addOption({
    name: "escrowContract",
    description: "EscrowAdapter contract address",
    defaultValue: "",
  })
  .addOption({
    name: "intexAuctionContract",
    description: "Auction contract address",
    defaultValue: "",
  })
  .addOption({
    name: "compactContract",
    description: "TheCompact contract address",
    defaultValue: "",
  })
  .addOption({
    name: "paymentToken",
    description: "PaymentToken address",
    defaultValue: "",
  })
  .setAction(lazy(escrowWireAction));

// ============================================================================
// TargetRouter Wire
// ============================================================================

const targetBridgeWireAction = async (args: TargetBridgeWireArgs, hre: unknown) => {
  const auction = (args.intexAuctionContract ?? "").trim();
  const intex = (args.intexContract ?? "").trim();
  const escrow = (args.escrowContract ?? "").trim();

  const empty: string[] = [];
  if (!auction) empty.push("--auction-contract");
  if (!intex) empty.push("--intex-contract");
  if (!escrow) empty.push("--escrow-contract");
  if (empty.length > 0) {
    throw new Error(
      `TargetRouter wire requires non-empty addresses. Missing: ${empty.join(", ")}. ` +
        `The deploy workflow reads them from dist/addresses/<network>.json - ensure the deploy step captured IntexAuction, IntexNFT1155, EscrowAdapter.`
    );
  }

  const viem = await getViemForWire(hre);

  console.log(`Wiring TargetRouter...`);
  console.log(`  Bridge: ${args.bridgeContract}`);
  console.log(`  Auction: ${auction}`);
  console.log(`  Intex: ${intex}`);
  console.log(`  Escrow: ${escrow}`);

  const bridge = (await viem.getContractAt(
    "TargetRouter",
    args.bridgeContract as `0x${string}`
  )) as {
    read: {
      auction: () => Promise<`0x${string}`>;
      intex: () => Promise<`0x${string}`>;
      escrowAdapter: () => Promise<`0x${string}`>;
    };
    write: {
      wire: (args: [`0x${string}`, `0x${string}`, `0x${string}`]) => Promise<`0x${string}`>;
    };
  };

  const [currentAuction, currentIntex, currentEscrow] = await Promise.all([
    bridge.read.auction(),
    bridge.read.intex(),
    bridge.read.escrowAdapter(),
  ]);

  const allMatch =
    currentAuction.toLowerCase() === auction.toLowerCase() &&
    currentIntex.toLowerCase() === intex.toLowerCase() &&
    currentEscrow.toLowerCase() === escrow.toLowerCase();

  if (allMatch) {
    console.log(`[OK] TargetRouter already wired to these contracts`);
    return;
  }

  if (currentAuction !== "0x0000000000000000000000000000000000000000") {
    const changed = [
      currentAuction.toLowerCase() !== auction.toLowerCase() && "auction",
      currentIntex.toLowerCase() !== intex.toLowerCase() && "intex",
      currentEscrow.toLowerCase() !== escrow.toLowerCase() && "escrow",
    ].filter(Boolean);
    console.log(`[sync] Rewiring TargetRouter (changed: ${changed.join(", ")})`);
  }

  const txHash = await sendAndWait(viem, () =>
    bridge.write.wire([
      auction as `0x${string}`,
      intex as `0x${string}`,
      escrow as `0x${string}`,
    ]),
  );
  console.log(`[OK] TargetRouter wired. Tx: ${txHash}`);
};

const targetBridgeWire = task("target-bridge-wire", "Wire TargetRouter to Auction, Intex, and EscrowAdapter")
  .addOption({
    name: "bridgeContract",
    description: "TargetRouter contract address",
    defaultValue: "",
  })
  .addOption({
    name: "intexAuctionContract",
    description: "Auction contract address",
    defaultValue: "",
  })
  .addOption({
    name: "intexContract",
    description: "IntexNFT1155 contract address",
    defaultValue: "",
  })
  .addOption({
    name: "escrowContract",
    description: "EscrowAdapter contract address",
    defaultValue: "",
  })
  .setAction(lazy(targetBridgeWireAction));

// ============================================================================
// OriginRouter Wire
// ============================================================================

const originBridgeWireAction = async (args: OriginBridgeWireArgs, hre: unknown) => {
  const viem = await getViemForWire(hre);
  
  console.log(`Wiring OriginRouter...`);
  console.log(`  Bridge: ${args.bridgeContract}`);
  console.log(`  Desis: ${args.desisContract}`);
  console.log(`  IntexFactory: ${args.intexFactoryContract}`);

  const bridge = (await viem.getContractAt(
    "OriginRouter",
    args.bridgeContract as `0x${string}`
  )) as {
    read: {
      desis: () => Promise<`0x${string}`>;
      intexFactory: () => Promise<`0x${string}`>;
    };
    write: {
      wire: (args: [`0x${string}`, `0x${string}`]) => Promise<`0x${string}`>;
    };
  };

  const ZERO = "0x0000000000000000000000000000000000000000";
  const [currentDesis, currentIntexFactory] = await Promise.all([
    bridge.read.desis(),
    bridge.read.intexFactory(),
  ]);

  const desisMatch = currentDesis.toLowerCase() === args.desisContract.toLowerCase();
  const intexFactoryMatch = currentIntexFactory.toLowerCase() === args.intexFactoryContract.toLowerCase();

  if (desisMatch && intexFactoryMatch) {
    console.log(`[OK] OriginRouter already wired to this Desis + IntexFactory`);
    return;
  }

  if (currentDesis !== ZERO) {
    console.log(`[sync] Rewiring OriginRouter`);
    if (!desisMatch) console.log(`   desis: ${currentDesis} -> ${args.desisContract}`);
    if (!intexFactoryMatch) console.log(`   intexFactory: ${currentIntexFactory} -> ${args.intexFactoryContract}`);
  }

  const txHash = await sendAndWait(viem, () =>
    bridge.write.wire([
      args.desisContract as `0x${string}`,
      args.intexFactoryContract as `0x${string}`,
    ]),
  );
  console.log(`[OK] OriginRouter wired. Tx: ${txHash}`);
};

const originBridgeWire = task("origin-bridge-wire", "Wire OriginRouter to Desis + IntexFactory")
  .addOption({
    name: "bridgeContract",
    description: "OriginRouter contract address",
    defaultValue: "",
  })
  .addOption({
    name: "desisContract",
    description: "Desis contract address",
    defaultValue: "",
  })
  .addOption({
    name: "intexFactoryContract",
    description: "IntexFactory contract address",
    defaultValue: "",
  })
  .setAction(lazy(originBridgeWireAction));

// ============================================================================
// IntexFactory Grant Roles
// Grant SETTLEMENT_ROLE on IntexNFT1155 to IntexFactory so it can call
// `intex.settle(...)` and burn Issued / mint Settled tokens.
// ============================================================================

interface SettlementGrantRolesArgs {
  settlementContract: string;
  intexContract: string;
}

const settlementGrantRolesAction = async (args: SettlementGrantRolesArgs, hre: unknown) => {
  const viem = await getViemForWire(hre);

  console.log(`Granting roles for IntexFactory...`);
  console.log(`  IntexFactory: ${args.settlementContract}`);
  console.log(`  IntexNFT1155: ${args.intexContract}`);

  const intex = (await viem.getContractAt(
    "IntexNFT1155",
    args.intexContract as `0x${string}`
  )) as {
    read: {
      SETTLEMENT_ROLE: () => Promise<`0x${string}`>;
      hasRole: (args: [`0x${string}`, `0x${string}`]) => Promise<boolean>;
    };
    write: {
      grantRole: (args: [`0x${string}`, `0x${string}`]) => Promise<`0x${string}`>;
    };
  };

  const settlementRole = await intex.read.SETTLEMENT_ROLE();
  const hasIntexRole = await intex.read.hasRole([
    settlementRole,
    args.settlementContract as `0x${string}`,
  ]);
  if (hasIntexRole) {
    console.log(`[OK] IntexNFT1155: IntexFactory already has SETTLEMENT_ROLE`);
  } else {
    const tx1 = await sendAndWait(viem, () =>
      intex.write.grantRole([
        settlementRole,
        args.settlementContract as `0x${string}`,
      ]),
    );
    console.log(`[OK] IntexNFT1155: SETTLEMENT_ROLE granted to IntexFactory. Tx: ${tx1}`);
  }
};

const settlementGrantRoles = task(
  "settlement-grant-roles",
  "Grant SETTLEMENT_ROLE on IntexNFT1155 to IntexFactory"
)
  .addOption({
    name: "settlementContract",
    description: "IntexFactory contract address",
    defaultValue: "",
  })
  .addOption({
    name: "intexContract",
    description: "IntexNFT1155 contract address on Outbe",
    defaultValue: "",
  })
  .setAction(lazy(settlementGrantRolesAction));

// ============================================================================
// Promis-burner Wire (grant PROMIS_ROLE on IntexNFT1155 to IntexFactory)
// IntexFactory.minePromis calls intex.burnSettled, which is gated by PROMIS_ROLE.
// ============================================================================

interface PromisWireArgs {
  settlementContract: string;
  intexContract: string;
}

const promisWireAction = async (args: PromisWireArgs, hre: unknown) => {
  const viem = await getViemForWire(hre);

  console.log(`Granting PROMIS_ROLE on IntexNFT1155...`);
  console.log(`  IntexFactory: ${args.settlementContract}`);
  console.log(`  IntexNFT1155: ${args.intexContract}`);

  const intex = (await viem.getContractAt(
    "IntexNFT1155",
    args.intexContract as `0x${string}`
  )) as {
    read: {
      PROMIS_ROLE: () => Promise<`0x${string}`>;
      hasRole: (args: [`0x${string}`, `0x${string}`]) => Promise<boolean>;
    };
    write: {
      grantRole: (args: [`0x${string}`, `0x${string}`]) => Promise<`0x${string}`>;
    };
  };

  const role = await intex.read.PROMIS_ROLE();
  const hasPromisRole = await intex.read.hasRole([role, args.settlementContract as `0x${string}`]);
  if (hasPromisRole) {
    console.log(`[OK] IntexNFT1155: IntexFactory already has PROMIS_ROLE`);
  } else {
    const tx = await sendAndWait(viem, () =>
      intex.write.grantRole([role, args.settlementContract as `0x${string}`]),
    );
    console.log(`[OK] IntexNFT1155: PROMIS_ROLE granted to IntexFactory. Tx: ${tx}`);
  }
};

const promisWire = task(
  "promis-wire",
  "Grant PROMIS_ROLE on IntexNFT1155 to IntexFactory (enables minePromis burn path)"
)
  .addOption({
    name: "settlementContract",
    description: "IntexFactory contract address",
    defaultValue: "",
  })
  .addOption({
    name: "intexContract",
    description: "IntexNFT1155 contract address on Outbe",
    defaultValue: "",
  })
  .setAction(lazy(promisWireAction));

// ============================================================================
// Gem-parking Wire (grant GEM_ROLE on IntexNFT1155 to the GemFactory precompile)
// GemFactory.setup_factory calls intex.parkIntex, which is gated by GEM_ROLE.
// ============================================================================

interface GemWireArgs {
  gemFactory: string;
  intexContract: string;
}

const gemWireAction = async (args: GemWireArgs, hre: unknown) => {
  const viem = await getViemForWire(hre);

  console.log(`Granting GEM_ROLE on IntexNFT1155...`);
  console.log(`  GemFactory: ${args.gemFactory}`);
  console.log(`  IntexNFT1155: ${args.intexContract}`);

  const intex = (await viem.getContractAt(
    "IntexNFT1155",
    args.intexContract as `0x${string}`
  )) as {
    read: {
      GEM_ROLE: () => Promise<`0x${string}`>;
      hasRole: (args: [`0x${string}`, `0x${string}`]) => Promise<boolean>;
    };
    write: {
      grantRole: (args: [`0x${string}`, `0x${string}`]) => Promise<`0x${string}`>;
    };
  };

  const role = await intex.read.GEM_ROLE();
  const hasGemRole = await intex.read.hasRole([role, args.gemFactory as `0x${string}`]);
  if (hasGemRole) {
    console.log(`[OK] IntexNFT1155: GemFactory already has GEM_ROLE`);
  } else {
    const tx = await sendAndWait(viem, () =>
      intex.write.grantRole([role, args.gemFactory as `0x${string}`]),
    );
    console.log(`[OK] IntexNFT1155: GEM_ROLE granted to GemFactory. Tx: ${tx}`);
  }
};

const gemWire = task(
  "gem-wire",
  "Grant GEM_ROLE on IntexNFT1155 to the GemFactory precompile (enables parkIntex burn path)"
)
  .addOption({
    name: "gemFactory",
    description: "GemFactory precompile address on Outbe",
    defaultValue: "",
  })
  .addOption({
    name: "intexContract",
    description: "IntexNFT1155 contract address on Outbe",
    defaultValue: "",
  })
  .setAction(lazy(gemWireAction));

// ============================================================================
// Precompile-caller Wire - grant roles to the EVM frames that initiate the
// gated calls: the begin-block system caller (auction stage sends + qualify/call
// mark sends) and the Desis precompile (clearing tick, where
// createSeries + issuance-instructions run in-process).
// ============================================================================

interface SystemGrantRolesArgs {
  bridgeContract: string;
  intexContract: string;
  systemAddress: string;
  desisContract: string;
}

const systemGrantRolesAction = async (args: SystemGrantRolesArgs, hre: unknown) => {
  const viem = await getViemForWire(hre);

  if (!args.bridgeContract || args.bridgeContract === "null") {
    throw new Error("bridgeContract (OriginRouter) is required");
  }
  if (!args.intexContract || args.intexContract === "null") {
    throw new Error("intexContract (IntexNFT1155) is required");
  }
  if (!args.systemAddress || args.systemAddress === "null") {
    throw new Error("systemAddress (OUTBE_SYSTEM_TX_ADDRESS) is required");
  }
  if (!args.desisContract || args.desisContract === "null") {
    throw new Error("desisContract (Desis precompile) is required");
  }
  const systemAddress = args.systemAddress as `0x${string}`;
  const desisAddress = args.desisContract as `0x${string}`;

  console.log(`Granting precompile-caller roles...`);
  console.log(`  SystemCaller:    ${systemAddress}`);
  console.log(`  Desis:           ${desisAddress}`);
  console.log(`  OriginRouter: ${args.bridgeContract}`);
  console.log(`  IntexNFT1155:    ${args.intexContract}`);

  const router = (await viem.getContractAt(
    "OriginRouter",
    args.bridgeContract as `0x${string}`
  )) as {
    read: {
      DESIS_ROLE: () => Promise<`0x${string}`>;
      INTEX_FACTORY_ROLE: () => Promise<`0x${string}`>;
      hasRole: (args: [`0x${string}`, `0x${string}`]) => Promise<boolean>;
    };
    write: {
      grantRole: (args: [`0x${string}`, `0x${string}`]) => Promise<`0x${string}`>;
    };
  };

  const intex = (await viem.getContractAt(
    "IntexNFT1155",
    args.intexContract as `0x${string}`
  )) as {
    read: {
      RELAYER_ROLE: () => Promise<`0x${string}`>;
      hasRole: (args: [`0x${string}`, `0x${string}`]) => Promise<boolean>;
    };
    write: {
      grantRole: (args: [`0x${string}`, `0x${string}`]) => Promise<`0x${string}`>;
    };
  };

  const grantOnRouter = async (label: string, role: `0x${string}`, addr: `0x${string}`) => {
    if (await router.read.hasRole([role, addr])) {
      console.log(`[OK] OriginRouter: ${addr} already has ${label}`);
    } else {
      const tx = await sendAndWait(viem, () => router.write.grantRole([role, addr]));
      console.log(`[OK] OriginRouter: ${label} -> ${addr}. Tx: ${tx}`);
    }
  };

  const grantOnIntex = async (label: string, role: `0x${string}`, addr: `0x${string}`) => {
    if (await intex.read.hasRole([role, addr])) {
      console.log(`[OK] IntexNFT1155: ${addr} already has ${label}`);
    } else {
      const tx = await sendAndWait(viem, () => intex.write.grantRole([role, addr]));
      console.log(`[OK] IntexNFT1155: ${label} -> ${addr}. Tx: ${tx}`);
    }
  };

  const desisRole = await router.read.DESIS_ROLE();
  const intexFactoryRole = await router.read.INTEX_FACTORY_ROLE();
  const relayerRole = await intex.read.RELAYER_ROLE();

  // Begin-block caller: auction stage sends (DESIS_ROLE), qualify/call mark
  // sends to BNB (INTEX_FACTORY_ROLE on OriginRouter), and the local NFT
  // markQualified / markCalled (RELAYER_ROLE) - all run from begin-block.
  await grantOnRouter("DESIS_ROLE", desisRole, systemAddress);
  await grantOnRouter("INTEX_FACTORY_ROLE", intexFactoryRole, systemAddress);
  await grantOnIntex("RELAYER_ROLE", relayerRole, systemAddress);

  // Desis precompile frame (clearing tick): issuance-instructions
  // (INTEX_FACTORY_ROLE) + createSeries (RELAYER_ROLE) run in-process here.
  await grantOnRouter("INTEX_FACTORY_ROLE", intexFactoryRole, desisAddress);
  await grantOnIntex("RELAYER_ROLE", relayerRole, desisAddress);
};

const systemGrantRoles = task(
  "outbe-system-grant-roles",
  "Grant precompile-caller roles: DESIS_ROLE + INTEX_FACTORY_ROLE to the begin-block system caller; INTEX_FACTORY_ROLE + RELAYER_ROLE to the Desis precompile"
)
  .addOption({
    name: "bridgeContract",
    description: "OriginRouter contract address",
    defaultValue: "",
  })
  .addOption({
    name: "intexContract",
    description: "IntexNFT1155 contract address on Outbe",
    defaultValue: "",
  })
  .addOption({
    name: "systemAddress",
    description: "Outbe begin-block system caller (OUTBE_SYSTEM_TX_ADDRESS)",
    defaultValue: "",
  })
  .addOption({
    name: "desisContract",
    description: "Desis precompile address (clearing-tick issuance frame)",
    defaultValue: "",
  })
  .setAction(lazy(systemGrantRolesAction));

// ============================================================================
// IntexFactory: Assert RELAYER_ROLE on IntexNFT1155 (deploy-time invariant)
// ============================================================================

interface IntexFactoryAssertRelayerRoleArgs {
  intexContract: string;
  desisContract: string;
  systemAddress: string;
}

const intexFactoryAssertRelayerRoleAction = async (args: IntexFactoryAssertRelayerRoleArgs, hre: unknown) => {
  const viem = await getViemForWire(hre);

  if (!args.intexContract || args.intexContract === "null") {
    throw new Error("intexContract (IntexNFT1155) is required to assert RELAYER_ROLE");
  }
  if (!args.desisContract || args.desisContract === "null") {
    throw new Error("desisContract (Desis precompile) is required to assert RELAYER_ROLE");
  }
  if (!args.systemAddress || args.systemAddress === "null") {
    throw new Error("systemAddress (OUTBE_SYSTEM_TX_ADDRESS) is required to assert RELAYER_ROLE");
  }
  const desisAddress = args.desisContract as `0x${string}`;
  const systemAddress = args.systemAddress as `0x${string}`;

  console.log(`Asserting RELAYER_ROLE on IntexNFT1155 for the issuance + mark callers...`);
  console.log(`  IntexNFT1155: ${args.intexContract}`);
  console.log(`  Desis:        ${desisAddress} (createSeries)`);
  console.log(`  SystemCaller: ${systemAddress} (markQualified / markCalled)`);

  const intex = (await viem.getContractAt(
    "IntexNFT1155",
    args.intexContract as `0x${string}`
  )) as {
    read: {
      RELAYER_ROLE: () => Promise<`0x${string}`>;
      hasRole: (args: [`0x${string}`, `0x${string}`]) => Promise<boolean>;
    };
  };

  // createSeries runs in the Desis clearing-tick frame;
  // markQualified / markCalled run from begin-block (the system caller). Both
  // need RELAYER_ROLE.
  const role = await intex.read.RELAYER_ROLE();
  for (const addr of [desisAddress, systemAddress]) {
    if (!(await intex.read.hasRole([role, addr]))) {
      throw new Error(
        `${addr} does NOT hold RELAYER_ROLE on IntexNFT1155 ${args.intexContract}. ` +
          `Issuance (createSeries) or qualify / call (markQualified / markCalled) will revert. ` +
          `Grant it first: outbe-system-grant-roles --bridge-contract <router> --intex-contract <intex> --system-address <system> --desis-contract <desis>.`,
      );
    }
  }

  console.log(`[OK] Desis precompile and system caller hold RELAYER_ROLE on IntexNFT1155`);
};

const intexFactoryAssertRelayerRole = task(
  "intex-factory-assert-relayer-role",
  "Assert the Desis precompile and the begin-block system caller hold RELAYER_ROLE on IntexNFT1155 (fails the deploy if missing)",
)
  .addOption({ name: "intexContract", description: "IntexNFT1155 contract address on Outbe", defaultValue: "" })
  .addOption({ name: "desisContract", description: "Desis precompile address (createSeries caller)", defaultValue: "" })
  .addOption({ name: "systemAddress", description: "Outbe begin-block system caller (markQualified / markCalled)", defaultValue: "" })
  .setAction(lazy(intexFactoryAssertRelayerRoleAction));

// ============================================================================
// Grant RELAYER_ROLE (inbound-delivery caller)
// ============================================================================

interface GrantRelayerRoleArgs {
  token: string;
  adapter: string;
  contract: string;
}

const grantRelayerRoleAction = async (args: GrantRelayerRoleArgs, hre: unknown) => {
  const viem = await getViemForWire(hre);
  const contractName = args.contract || "IntexNFT1155";

  console.log(`Granting RELAYER_ROLE on ${contractName} @ ${args.token} to ${args.adapter}...`);

  const token = (await viem.getContractAt(contractName, args.token as `0x${string}`)) as {
    read: {
      RELAYER_ROLE: () => Promise<`0x${string}`>;
      hasRole: (args: [`0x${string}`, `0x${string}`]) => Promise<boolean>;
    };
    write: {
      grantRole: (args: [`0x${string}`, `0x${string}`]) => Promise<`0x${string}`>;
    };
  };

  const role = await token.read.RELAYER_ROLE();
  if (await token.read.hasRole([role, args.adapter as `0x${string}`])) {
    console.log("[OK] RELAYER_ROLE already granted");
    return;
  }

  const txHash = await sendAndWait(viem, () => token.write.grantRole([role, args.adapter as `0x${string}`]));
  console.log(`[OK] RELAYER_ROLE granted. Tx: ${txHash}`);
};

const grantRelayerRole = task(
  "grant-relayer-role",
  "Grant RELAYER_ROLE on an app contract (IntexAuction, EscrowAdapter, IntexNFT1155) to a bridge client",
)
  .addOption({ name: "token", description: "App contract that gates inbound calls by RELAYER_ROLE", defaultValue: "" })
  .addOption({ name: "adapter", description: "Bridge client to grant RELAYER_ROLE to (router or NFT bridge)", defaultValue: "" })
  .addOption({ name: "contract", description: "App contract name: IntexAuction | EscrowAdapter | IntexNFT1155 (default: IntexNFT1155)", defaultValue: "" })
  .setAction(lazy(grantRelayerRoleAction));

// ============================================================================
// Export
// ============================================================================

export const wireTasks = [
  auctionWire.build(),
  escrowWire.build(),
  targetBridgeWire.build(),
  originBridgeWire.build(),
  systemGrantRoles.build(),
  intexFactoryAssertRelayerRole.build(),
  settlementGrantRoles.build(),
  promisWire.build(),
  gemWire.build(),
  grantRelayerRole.build(),
];
