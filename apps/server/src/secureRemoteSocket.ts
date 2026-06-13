// FILE: secureRemoteSocket.ts
// Purpose: Wraps an Effect socket with the Synara secure remote encrypted frame protocol.
// Layer: Server WebSocket transport

import {
  createServerHello,
  decryptSecureFrame,
  deriveServerSession,
  encryptSecureFrame,
  parseSecureControlMessage,
  serializeSecureControlMessage,
  verifyClientAuth,
  type SecureClientAuth,
  type SecureClientHello,
  type SecureFrame,
  type SecureRemoteIdentity,
  type SecureServerHello,
  type SecureTransportSession,
} from "@t3tools/shared/secureRemote";
import { Effect } from "effect";
import * as Socket from "effect/unstable/socket/Socket";

function toBytes(chunk: string | Uint8Array): Uint8Array {
  return typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk;
}

function socketReadError(cause: unknown): Socket.SocketError {
  return new Socket.SocketError({
    reason: new Socket.SocketReadError({ cause }),
  });
}

function socketWriteError(cause: unknown): Socket.SocketError {
  return new Socket.SocketError({
    reason: new Socket.SocketWriteError({ cause }),
  });
}

export function makeSecureRemoteServerSocket(input: {
  readonly socket: Socket.Socket;
  readonly serverIdentity: SecureRemoteIdentity;
  readonly expectedClientIdentityPublicKey: string;
}): Socket.Socket {
  let clientHello: SecureClientHello | null = null;
  let serverHello: SecureServerHello | null = null;
  let serverEphemeralSecretKey: Uint8Array | null = null;
  let session: SecureTransportSession | null = null;

  const runRaw: Socket.Socket["runRaw"] = (handler, options) =>
    Effect.scoped(
      Effect.gen(function* () {
        const rawWrite = yield* input.socket.writer;
        return yield* input.socket.runRaw((data) =>
          Effect.gen(function* () {
            if (!session) {
              const message = parseSecureControlMessage(data);
              if (!clientHello) {
                const pending = createServerHello({
                  clientHello: message as SecureClientHello,
                  serverIdentity: input.serverIdentity,
                });
                clientHello = message as SecureClientHello;
                serverHello = pending.hello;
                serverEphemeralSecretKey = pending.serverEphemeralSecretKey;
                yield* rawWrite(serializeSecureControlMessage(pending.hello));
                return;
              }

              verifyClientAuth({
                clientHello,
                serverHello: serverHello!,
                clientAuth: message as SecureClientAuth,
                expectedClientIdentityPublicKey: input.expectedClientIdentityPublicKey,
              });
              session = deriveServerSession({
                clientHello,
                serverHello: serverHello!,
                serverEphemeralSecretKey: serverEphemeralSecretKey!,
              });
              return;
            }

            const frame = parseSecureControlMessage(data) as SecureFrame;
            const plaintext = decryptSecureFrame(session, frame);
            const result = handler(plaintext);
            if (Effect.isEffect(result)) {
              yield* result;
            }
          }).pipe(Effect.mapError(socketReadError)),
          options,
        );
      }),
    );

  const run: Socket.Socket["run"] = (handler, options) =>
    runRaw((data) => {
      const bytes = toBytes(data);
      const result = handler(bytes);
      return Effect.isEffect(result) ? result : undefined;
    }, options);

  const writer: Socket.Socket["writer"] = input.socket.writer.pipe(
    Effect.map(
      (rawWrite) => (chunk) =>
        Effect.try({
          try: () => {
            if (Socket.isCloseEvent(chunk)) {
              return chunk;
            }
            if (!session) {
              throw new Error("Secure remote session is not established.");
            }
            return serializeSecureControlMessage(encryptSecureFrame(session, toBytes(chunk)));
          },
          catch: socketWriteError,
        }).pipe(Effect.flatMap(rawWrite)),
    ),
  );

  return Socket.Socket.of({
    [Socket.TypeId]: Socket.TypeId,
    run,
    runRaw,
    writer,
  });
}
