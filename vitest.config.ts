import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    pool: "threads",
    hookTimeout: 180000,
    testTimeout: 180000,
    setupFiles: ["./test/setup.ts"],
    server: {
      deps: {
        // This tells Vitest to fix the missing extensions for this specific library on the fly
        inline: [/@majikah\/majik-key/, /@majikah\/majik-contact/],
      },
    },
  },
});
