import "@testing-library/jest-dom";

import { BroadcastChannel as NodeBroadcastChannel } from "node:worker_threads";

// JSDOM 24 (current devDependency) does not expose BroadcastChannel
// on its window object. Tests for H-004 cross-tab session sync need
// it so we polyfill from Node's node:worker_threads — same shape
// (name, postMessage, close, onmessage, addEventListener), scoped
// to the test process which is what we want anyway.
//
// This is strictly test infra; production browsers ship
// BroadcastChannel natively (Chrome 54+, Firefox 38+, Safari 15.4+)
// so the production path is unchanged.
if (typeof globalThis.BroadcastChannel === "undefined") {
  (globalThis as { BroadcastChannel: typeof BroadcastChannel }).BroadcastChannel =
    NodeBroadcastChannel as unknown as typeof BroadcastChannel;
}
