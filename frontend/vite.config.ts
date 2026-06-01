import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Anchorix dev config:
// - dev server proxies /api to the local control plane so the SPA never
//   needs to know about CORS in development.
// - production builds emit static assets that can be served by the API
//   container or any static host.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: "0.0.0.0",
    proxy: {
      "/api": {
        target: process.env.VITE_API_PROXY_TARGET ?? "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    globals: true,
  },
});
