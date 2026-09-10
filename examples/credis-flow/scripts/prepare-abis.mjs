// Aggregates ABI JSON files for the credis-flow demo from canonical sources
// under outbe-chain/contracts/, normalizing every output to {abi: [...]}.
//
// Run via `npm run prepare-abis` (also chained from `npm run generate-types`).

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(here, "..");
const repoContracts = resolve(projectRoot, "../../contracts");
const outDir = resolve(projectRoot, "abi");

// Output name (typechain consumes this as the contract type name) -> source path.
const MAPPING = {
  IGratis: "precompiles/abi-export/IGratis.json",
  IGratisFactory: "precompiles/abi-export/IGratisFactory.json",
  IPromis: "precompiles/abi-export/IPromis.json",
  IPromisFactory: "precompiles/abi-export/IPromisFactory.json",
  IGem: "precompiles/abi-export/IGem.json",
  IGemFactory: "precompiles/abi-export/IGemFactory.json",
  ICredis: "precompiles/abi-export/ICredis.json",
  ICredisFactory: "precompiles/abi-export/ICredisFactory.json",
  IFidelity: "precompiles/abi-export/IFidelity.json",
  IVaultRouter: "precompiles/abi-export/IVaultRouter.json",
  SmartAccountFactory: "smart-account/abi-export/SmartAccountFactory.json",
  ITokenBundle: "smart-account/abi-export/ITokenBundle.json",
  IEntryPoint: "smart-account/abi-export/IEntryPoint.json",
  IERC20: "smart-account/abi-export/IERC20.json"
};

function extractAbi(name, sourcePath) {
  if (!existsSync(sourcePath)) {
    throw new Error(`prepare-abis: missing source ABI for ${name} at ${sourcePath}`);
  }
  const parsed = JSON.parse(readFileSync(sourcePath, "utf8"));
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed?.abi)) return parsed.abi;
  throw new Error(
    `prepare-abis: unrecognized ABI shape for ${name} at ${sourcePath} (expected array or {abi: [...]})`,
  );
}

if (existsSync(outDir)) rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

for (const [name, relSource] of Object.entries(MAPPING)) {
  const sourcePath = resolve(repoContracts, relSource);
  const abi = extractAbi(name, sourcePath);
  const destPath = resolve(outDir, `${name}.json`);
  writeFileSync(destPath, `${JSON.stringify({ abi }, null, 2)}\n`);
  console.log(`prepare-abis: wrote abi/${name}.json (${abi.length} entries) <- ${relSource}`);
}

console.log(`prepare-abis: ${Object.keys(MAPPING).length} ABI files staged in ${outDir}`);
