/**
 * Fail if any registry method is absent from the generated contract ABIs.
 *
 * `pick()` / `pickEvent()` throw at module load, so importing the registries is
 * the whole check - it needs no RPC and no network. Run in CI whenever the mcp
 * sources or any generated `abi-export` artifact changes.
 */
import { CONTRACTS } from "../src/registry.js";
import * as intent from "../src/intent/registry.js";
import * as intex from "../src/intex/registry.js";

const precompileMethods = Object.values(CONTRACTS).reduce((n, c) => n + c.abi.length, 0);
const external = [intent.ROUTER_ABI, intent.ERC20_ABI, intex.AUCTION_ABI, intex.NFT_ABI].length;

console.log(
  `ok - ${Object.keys(CONTRACTS).length} precompiles / ${precompileMethods} methods ` +
    `and ${external} external ABIs resolved against contracts/*/abi-export`,
);
