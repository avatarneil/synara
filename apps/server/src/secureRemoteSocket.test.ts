// FILE: secureRemoteSocket.test.ts
// Purpose: Verifies the server-side secure remote socket wrapper handshake and frame encryption.
// Layer: Server transport tests

import {
  createClientAuth,
  createClientHello,
  decryptSecureFrame,
  deriveClientSession,
  encryptSecureFrame,
  generateSecureRemoteIdentity,
  parseSecureControlMessage,
  serializeSecureControlMessage,
  type SecureFrame,
  type SecureServerHello,
  type SecureTransportSession,
} from "@t3tools/shared/secureRemote";
import { Effect } from "effect";
import * as Socket from "effect/unstable/socket/Socket";
import { describe, expect, it } from "vitest";

import { makeSecureRemoteServerSocket } from "./secureRemoteSocket";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

describe("makeSecureRemoteServerSocket", () => {
  it("authenticates the paired client and decrypts/encrypts transport frames", async () => {
    const clientIdentity = generateSecureRemoteIdentity();
    const serverIdentity = generateSecureRemoteIdentity();
    const expectedServer = {
      protocol: "synara-remote-e2ee-v1" as const,
      serverDeviceId: serverIdentity.deviceId,
      serverIdentityPublicKey: serverIdentity.identityPublicKey,
    };
    const pendingClient = createClientHello({ clientIdentity, expectedServer });
    const rawWrites: Array<string | Uint8Array | Socket.CloseEvent> = [];
    let clientSession: SecureTransportSession | null = null;

    const rawSocket = Socket.Socket.of({
      [Socket.TypeId]: Socket.TypeId,
      runRaw: (handler, options) =>
        Effect.gen(function* () {
          if (options?.onOpen) yield* options.onOpen;
          const firstResult = handler(serializeSecureControlMessage(pendingClient.hello));
          if (Effect.isEffect(firstResult)) yield* firstResult;

          const serverHello = parseSecureControlMessage(
            rawWrites[0] as string,
          ) as SecureServerHello;
          const clientAuth = createClientAuth({
            clientHello: pendingClient.hello,
            serverHello,
            clientIdentity,
          });
          clientSession = deriveClientSession({
            clientHello: pendingClient.hello,
            serverHello,
            clientEphemeralSecretKey: pendingClient.clientEphemeralSecretKey,
            expectedServer,
          });

          const authResult = handler(serializeSecureControlMessage(clientAuth));
          if (Effect.isEffect(authResult)) yield* authResult;

          const frameResult = handler(
            serializeSecureControlMessage(
              encryptSecureFrame(clientSession, encoder.encode("from client")),
            ),
          );
          if (Effect.isEffect(frameResult)) yield* frameResult;
        }),
      run: (handler, options) =>
        rawSocket.runRaw((data) => {
          const bytes = typeof data === "string" ? encoder.encode(data) : data;
          const result = handler(bytes);
          return Effect.isEffect(result) ? result : undefined;
        }, options),
      writer: Effect.succeed((chunk) =>
        Effect.sync(() => {
          rawWrites.push(chunk);
        }),
      ),
    });

    const secureSocket = makeSecureRemoteServerSocket({
      socket: rawSocket,
      serverIdentity,
      expectedClientIdentityPublicKey: clientIdentity.identityPublicKey,
    });
    const received: Uint8Array[] = [];

    await Effect.runPromise(
      secureSocket.runRaw((data) =>
        Effect.sync(() => {
          received.push(typeof data === "string" ? encoder.encode(data) : data);
        }),
      ),
    );

    expect(decoder.decode(received[0])).toBe("from client");

    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const write = yield* secureSocket.writer;
          yield* write(encoder.encode("from server"));
        }),
      ),
    );

    const encryptedServerFrame = parseSecureControlMessage(rawWrites[1] as string) as SecureFrame;
    expect(decoder.decode(decryptSecureFrame(clientSession!, encryptedServerFrame))).toBe(
      "from server",
    );
  });
});
