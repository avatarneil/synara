// FILE: secureRemoteWebSocket.test.ts
// Purpose: Verifies the browser-side secure remote WebSocket adapter handshake and frame encryption.
// Layer: Web transport tests

import {
  createServerHello,
  decryptSecureFrame,
  deriveServerSession,
  encryptSecureFrame,
  generateSecureRemoteIdentity,
  parseSecureControlMessage,
  serializeSecureControlMessage,
  verifyClientAuth,
  type SecureClientAuth,
  type SecureClientHello,
  type SecureFrame,
  type SecureServerHello,
} from "@t3tools/shared/secureRemote";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SecureRemoteWebSocket } from "./secureRemoteWebSocket";

type Listener = (event: { data?: unknown; code?: number; reason?: string }) => void;
type EventType = "open" | "message" | "close" | "error";

const sockets: MockNativeWebSocket[] = [];

class MockNativeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  readyState = MockNativeWebSocket.CONNECTING;
  binaryType: BinaryType = "arraybuffer";
  readonly sent: unknown[] = [];
  private readonly listeners = new Map<EventType, Set<Listener>>();

  constructor(readonly url: string) {
    sockets.push(this);
  }

  addEventListener(type: EventType, listener: Listener) {
    const listeners = this.listeners.get(type) ?? new Set<Listener>();
    listeners.add(listener);
    this.listeners.set(type, listeners);
  }

  removeEventListener(type: EventType, listener: Listener) {
    this.listeners.get(type)?.delete(listener);
  }

  send(data: unknown) {
    this.sent.push(data);
  }

  close(code = 1000, reason = "") {
    this.readyState = MockNativeWebSocket.CLOSED;
    this.emit("close", { code, reason });
  }

  emit(type: EventType, event: { data?: unknown; code?: number; reason?: string } = {}) {
    for (const listener of this.listeners.get(type) ?? []) {
      listener(event);
    }
  }
}

const originalWebSocket = globalThis.WebSocket;

beforeEach(() => {
  sockets.length = 0;
  globalThis.WebSocket = MockNativeWebSocket as unknown as typeof WebSocket;
});

afterEach(() => {
  globalThis.WebSocket = originalWebSocket;
  vi.restoreAllMocks();
});

describe("SecureRemoteWebSocket", () => {
  it("handshakes with signed identities and encrypts frames in both directions", async () => {
    const clientIdentity = generateSecureRemoteIdentity();
    const serverIdentity = generateSecureRemoteIdentity();
    const expectedServer = {
      protocol: "synara-remote-e2ee-v1" as const,
      serverDeviceId: serverIdentity.deviceId,
      serverIdentityPublicKey: serverIdentity.identityPublicKey,
    };
    const secureSocket = new SecureRemoteWebSocket("ws://100.64.0.10:6767/ws?secure=1", undefined, {
      nativeWebSocket: MockNativeWebSocket as unknown as typeof WebSocket,
      clientIdentity,
      trustedServer: expectedServer,
    });
    const nativeSocket = sockets[0]!;
    const openListener = vi.fn();
    const messageListener = vi.fn();
    secureSocket.addEventListener("open", openListener);
    secureSocket.addEventListener("message", messageListener);

    nativeSocket.emit("open");
    const clientHello = parseSecureControlMessage(nativeSocket.sent[0] as string) as SecureClientHello;
    const pendingServer = createServerHello({ clientHello, serverIdentity });
    nativeSocket.emit("message", {
      data: serializeSecureControlMessage(pendingServer.hello),
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const clientAuth = parseSecureControlMessage(nativeSocket.sent[1] as string) as SecureClientAuth;
    verifyClientAuth({
      clientHello,
      serverHello: pendingServer.hello,
      clientAuth,
      expectedClientIdentityPublicKey: clientIdentity.identityPublicKey,
    });
    const serverSession = deriveServerSession({
      clientHello,
      serverHello: pendingServer.hello as SecureServerHello,
      serverEphemeralSecretKey: pendingServer.serverEphemeralSecretKey,
    });

    expect(openListener).toHaveBeenCalledTimes(1);
    expect(secureSocket.readyState).toBe(WebSocket.OPEN);

    nativeSocket.emit("message", {
      data: serializeSecureControlMessage(
        encryptSecureFrame(serverSession, new TextEncoder().encode("from server")),
      ),
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(new TextDecoder().decode(messageListener.mock.calls[0][0].data)).toBe("from server");

    secureSocket.send(new TextEncoder().encode("from client"));
    const encryptedClientFrame = parseSecureControlMessage(
      nativeSocket.sent[2] as string,
    ) as SecureFrame;
    expect(new TextDecoder().decode(decryptSecureFrame(serverSession, encryptedClientFrame))).toBe(
      "from client",
    );
  });
});
