// test/setup.ts
//
// OPTIONAL safety net — only needed if your Node/runner doesn't already
// expose WebCrypto globally. This wires up Node's REAL `webcrypto`
// implementation, not a mock, so behavior matches what runs in browsers
// or modern Node (v19+, where globalThis.crypto is built in by default).
//
// To use: add to vitest.config.ts ->
//   export default defineConfig({
//     test: { setupFiles: ["./test/setup.ts"] }
//   });

import { webcrypto } from "node:crypto";

if (!globalThis.crypto?.subtle) {
  globalThis.crypto = webcrypto as unknown as Crypto;
}
