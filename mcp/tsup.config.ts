import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node18",
  clean: true,
  bundle: true,
  // Keep deps external - `npx` installs them from package.json. Bundling viem +
  // noble would bloat dist and risk dual-package issues.
  banner: { js: "#!/usr/bin/env node" },
});
