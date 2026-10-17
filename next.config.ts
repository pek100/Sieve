import type { NextConfig } from "next";

// Static export: Tauri loads `out/` as files, so there is no Next server at runtime.
const nextConfig: NextConfig = {
  output: "export",
  images: { unoptimized: true },
  trailingSlash: true,
  // No dev-only "N" bubble in the window (node_modules/next/dist/docs, devIndicators):
  // errors still surface. It overlapped the bottom-left of the app under `pnpm tauri dev`.
  devIndicators: false,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
