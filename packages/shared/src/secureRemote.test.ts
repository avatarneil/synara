// FILE: secureRemote.test.ts
// Purpose: Verifies secure remote pairing handshake and encrypted frames.
// Layer: Shared runtime tests

import { describe, expect, it } from "vitest";

import {
  SECURE_REMOTE_PROTOCOL,
  buildSecurePairingUrl,
  createClientAuth,
  createClientHello,
  createSecurePairingPayload,
  createServerHello,
  decodeSecurePairingPayload,
  decryptSecureFrame,
  deriveClientSession,
  deriveServerSession,
  encryptSecureFrame,
  generateSecureRemoteIdentity,
  verifyClientAuth,
  verifyServerHello,
} from "./secureRemote";

describe("secureRemote", () => {
  it("round-trips secure pairing payloads in pairing URLs", () => {
    const serverIdentity = generateSecureRemoteIdentity();
    const payload = createSecurePairingPayload({
      origin: "http://100.64.0.10:6767",
      credential: "ABCD2345",
      expiresAt: "2026-06-13T05:00:00.000Z",
      serverIdentity: {
        protocol: SECURE_REMOTE_PROTOCOL,
        serverDeviceId: serverIdentity.deviceId,
        serverIdentityPublicKey: serverIdentity.identityPublicKey,
      },
    });

    const url = new URL(buildSecurePairingUrl(payload.origin, payload));
    const params = new URLSearchParams(url.hash.slice(1));

    expect(params.get("token")).toBe("ABCD2345");
    expect(decodeSecurePairingPayload(params.get("secure") ?? "")).toEqual(payload);
  });

  it("derives matching directional keys and encrypts frames", () => {
    const serverIdentity = generateSecureRemoteIdentity();
    const clientIdentity = generateSecureRemoteIdentity();
    const expectedServer = {
      protocol: SECURE_REMOTE_PROTOCOL,
      serverDeviceId: serverIdentity.deviceId,
      serverIdentityPublicKey: serverIdentity.identityPublicKey,
    };
    const pendingClient = createClientHello({ clientIdentity, expectedServer });
    const pendingServer = createServerHello({
      clientHello: pendingClient.hello,
      serverIdentity,
    });

    expect(() =>
      verifyServerHello({
        clientHello: pendingClient.hello,
        serverHello: pendingServer.hello,
        expectedServer,
      }),
    ).not.toThrow();

    const clientAuth = createClientAuth({
      clientHello: pendingClient.hello,
      serverHello: pendingServer.hello,
      clientIdentity,
    });
    expect(() =>
      verifyClientAuth({
        clientHello: pendingClient.hello,
        serverHello: pendingServer.hello,
        clientAuth,
        expectedClientIdentityPublicKey: clientIdentity.identityPublicKey,
      }),
    ).not.toThrow();

    const clientSession = deriveClientSession({
      clientHello: pendingClient.hello,
      serverHello: pendingServer.hello,
      clientEphemeralSecretKey: pendingClient.clientEphemeralSecretKey,
      expectedServer,
    });
    const serverSession = deriveServerSession({
      clientHello: pendingClient.hello,
      serverHello: pendingServer.hello,
      serverEphemeralSecretKey: pendingServer.serverEphemeralSecretKey,
    });

    const clientFrame = encryptSecureFrame(clientSession, new TextEncoder().encode("hello"));
    expect(new TextDecoder().decode(decryptSecureFrame(serverSession, clientFrame))).toBe("hello");

    const serverFrame = encryptSecureFrame(serverSession, new TextEncoder().encode("world"));
    expect(new TextDecoder().decode(decryptSecureFrame(clientSession, serverFrame))).toBe("world");
  });

  it("rejects replayed frames", () => {
    const serverIdentity = generateSecureRemoteIdentity();
    const clientIdentity = generateSecureRemoteIdentity();
    const expectedServer = {
      protocol: SECURE_REMOTE_PROTOCOL,
      serverDeviceId: serverIdentity.deviceId,
      serverIdentityPublicKey: serverIdentity.identityPublicKey,
    };
    const pendingClient = createClientHello({ clientIdentity, expectedServer });
    const pendingServer = createServerHello({
      clientHello: pendingClient.hello,
      serverIdentity,
    });
    const clientSession = deriveClientSession({
      clientHello: pendingClient.hello,
      serverHello: pendingServer.hello,
      clientEphemeralSecretKey: pendingClient.clientEphemeralSecretKey,
      expectedServer,
    });
    const serverSession = deriveServerSession({
      clientHello: pendingClient.hello,
      serverHello: pendingServer.hello,
      serverEphemeralSecretKey: pendingServer.serverEphemeralSecretKey,
    });

    const frame = encryptSecureFrame(clientSession, new TextEncoder().encode("once"));
    decryptSecureFrame(serverSession, frame);

    expect(() => decryptSecureFrame(serverSession, frame)).toThrow(/replay|out-of-order/u);
  });
});
