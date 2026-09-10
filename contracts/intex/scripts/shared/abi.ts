// Contract ABIs from forge abi-export (this module + the precompiles module).

import * as fs from "fs";
import { type Abi } from "viem";

// Origin precompiles expose their ABI under the I-prefixed interface name.
const PRECOMPILE_INTERFACE: Record<string, string> = {
  Desis: "IDesis",
  IntexFactory: "IIntexFactory",
};

export function loadAbi(name: string): Abi {
  if (name in PRECOMPILE_INTERFACE) {
    const p = `../precompiles/abi-export/${PRECOMPILE_INTERFACE[name]}.json`;
    if (!fs.existsSync(p)) throw new Error(`ABI not found: ${name} (${p})`);
    return JSON.parse(fs.readFileSync(p, "utf-8")) as Abi;
  }
  const p = `abi-export/${name}.json`;
  if (!fs.existsSync(p)) throw new Error(`ABI not found: ${name} (${p})`);
  return (JSON.parse(fs.readFileSync(p, "utf-8")) as { abi: Abi }).abi;
}
