// FILE: wsTransport.test.ts
// Purpose: Verifies browser WebSocket construction around the Effect RPC transport.
// Layer: Web transport tests
// Depends on: the global WebSocket constructor shim and desktop bridge URL contract.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WS_CHANNELS } from "@t3tools/contracts";
import {
  createSecurePairingPayload,
  generateSecureRemoteIdentity,
} from "@t3tools/shared/secureRemote";

import { saveTrustedSecureRemoteServer } from "./lib/secureRemoteState";
import { shouldKeepServerLifecycleStream, WsTransport } from "./wsTransport";

type WsEventType = "open" | "message" | "close" | "error";
type WsListener = (event?: { data?: unknown }) => void;

const sockets: MockWebSocket[] = [];

class MockWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  readyState = MockWebSocket.CONNECTING;
  readonly sent: unknown[] = [];
  private readonly listeners = new Map<WsEventType, Set<WsListener>>();

  constructor(readonly url: string) {
    sockets.push(this);
  }

  addEventListener(type: WsEventType, listener: WsListener) {
    const listeners = this.listeners.get(type) ?? new Set<WsListener>();
    listeners.add(listener);
    this.listeners.set(type, listeners);
  }

  removeEventListener(type: WsEventType, listener: WsListener) {
    this.listeners.get(type)?.delete(listener);
  }

  send(data: unknown) {
    this.sent.push(data);
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    this.emit("close");
  }

  private emit(type: WsEventType, event?: { data?: unknown }) {
    const listeners = this.listeners.get(type);
    if (!listeners) return;
    for (const listener of listeners) {
      listener(event);
    }
  }
}

const originalWebSocket = globalThis.WebSocket;
const originalFetch = globalThis.fetch;

function createMemoryStorage(): Storage {
  const values = new Map<string, string>();
  return {
    get length() {
      return values.size;
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => values.delete(key),
    setItem: (key, value) => values.set(key, value),
  };
}

async function waitForSocket(): Promise<MockWebSocket> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const socket = sockets.at(-1);
    if (socket) {
      return socket;
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("Expected WebSocket to be created");
}

beforeEach(() => {
  sockets.length = 0;
  vi.stubEnv("VITE_WS_URL", "");
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: false,
      json: async () => null,
    }),
  );

  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: {
        protocol: "http:",
        hostname: "localhost",
        port: "3020",
        origin: "http://localhost:3020",
        href: "http://localhost:3020/",
        search: "",
        hash: "",
      },
      localStorage: createMemoryStorage(),
      desktopBridge: undefined,
    },
  });

  globalThis.WebSocket = MockWebSocket as unknown as typeof WebSocket;
});

afterEach(() => {
  globalThis.WebSocket = originalWebSocket;
  globalThis.fetch = originalFetch;
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("WsTransport", () => {
  it("keeps the shared lifecycle stream while either lifecycle channel is active", () => {
    expect(shouldKeepServerLifecycleStream(new Set([WS_CHANNELS.serverWelcome]))).toBe(true);
    expect(shouldKeepServerLifecycleStream(new Set([WS_CHANNELS.serverMaintenanceUpdated]))).toBe(
      true,
    );
    expect(
      shouldKeepServerLifecycleStream(
        new Set([WS_CHANNELS.serverWelcome, WS_CHANNELS.serverMaintenanceUpdated]),
      ),
    ).toBe(true);
    expect(shouldKeepServerLifecycleStream(new Set([WS_CHANNELS.serverConfigUpdated]))).toBe(false);
  });

  it("normalizes explicit websocket URLs to the RPC endpoint", async () => {
    const transport = new WsTransport("ws://localhost:3020");
    const socket = await waitForSocket();

    expect(socket.url).toBe("ws://localhost:3020/ws");

    transport.dispose();
  });

  it("uses the desktop bridge URL before falling back to the browser location", async () => {
    const getWsUrl = vi.fn().mockReturnValue("ws://127.0.0.1:53036/?token=old");
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: {
        location: { protocol: "http:", hostname: "localhost", port: "3020" },
        localStorage: createMemoryStorage(),
        desktopBridge: { getWsUrl },
      },
    });

    const transport = new WsTransport();
    const socket = await waitForSocket();

    expect(getWsUrl).toHaveBeenCalledTimes(1);
    expect(socket.url).toBe("ws://127.0.0.1:53036/ws?token=old");

    transport.dispose();
  });

  it("falls back to the current browser host when no desktop bridge URL exists", async () => {
    const transport = new WsTransport();
    const socket = await waitForSocket();

    expect(socket.url).toBe("ws://localhost:3020/ws");

    transport.dispose();
  });

  it("forwards page URL auth tokens to the websocket connection", async () => {
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: {
        location: {
          protocol: "http:",
          hostname: "100.64.0.10",
          port: "3773",
          origin: "http://100.64.0.10:3773",
          href: "http://100.64.0.10:3773/?token=remote-secret",
          search: "?token=remote-secret",
          hash: "",
        },
        localStorage: createMemoryStorage(),
        desktopBridge: undefined,
      },
    });

    const transport = new WsTransport();
    const socket = await waitForSocket();

    expect(socket.url).toBe("ws://100.64.0.10:3773/ws?token=remote-secret");

    transport.dispose();
  });

  it("appends a wsToken from the auth endpoint for paired browser sessions", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValue({
      ok: true,
      json: async () => ({ token: "paired-ws-token" }),
    } as Response);

    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: {
        location: {
          protocol: "http:",
          hostname: "100.64.0.10",
          port: "3773",
          origin: "http://100.64.0.10:3773",
          href: "http://100.64.0.10:3773/",
          search: "",
          hash: "",
        },
        localStorage: createMemoryStorage(),
        desktopBridge: undefined,
      },
    });

    const transport = new WsTransport();
    const socket = await waitForSocket();

    expect(globalThis.fetch).toHaveBeenCalledWith(
      "http://100.64.0.10:3773/api/auth/ws-token",
      expect.objectContaining({ method: "POST", credentials: "include" }),
    );
    expect(socket.url).toBe("ws://100.64.0.10:3773/ws?wsToken=paired-ws-token");

    transport.dispose();
  });

  it("uses encrypted websocket transport for trusted paired servers", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValue({
      ok: true,
      json: async () => ({ token: "paired-ws-token" }),
    } as Response);

    const serverIdentity = generateSecureRemoteIdentity();
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: {
        location: {
          protocol: "http:",
          hostname: "100.64.0.10",
          port: "3773",
          origin: "http://100.64.0.10:3773",
          href: "http://100.64.0.10:3773/",
          search: "",
          hash: "",
        },
        localStorage: createMemoryStorage(),
        desktopBridge: undefined,
      },
    });
    saveTrustedSecureRemoteServer(
      createSecurePairingPayload({
        origin: "http://100.64.0.10:3773",
        credential: "PAIRINGTOKEN",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        serverIdentity: {
          protocol: "synara-remote-e2ee-v1",
          serverDeviceId: serverIdentity.deviceId,
          serverIdentityPublicKey: serverIdentity.identityPublicKey,
        },
      }),
    );

    const transport = new WsTransport();
    const socket = await waitForSocket();

    expect(socket.url).toBe("ws://100.64.0.10:3773/ws?wsToken=paired-ws-token&secure=1");

    transport.dispose();
  });

  it("notifies state listeners and replays the current state on demand", () => {
    const transport = new WsTransport();
    const listener = vi.fn();

    const unsubscribe = transport.onStateChange(listener, { replayCurrent: true });

    expect(listener).toHaveBeenCalledWith("connecting");

    listener.mockClear();
    transport.dispose();

    expect(listener).toHaveBeenCalledWith("disposed");

    listener.mockClear();
    unsubscribe();
    transport.dispose();

    expect(listener).not.toHaveBeenCalled();
  });
});
