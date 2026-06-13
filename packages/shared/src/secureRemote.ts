// FILE: secureRemote.ts
// Purpose: Shared remote pairing encryption protocol primitives.
// Layer: Shared runtime utilities

import { gcm } from "@noble/ciphers/aes.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

export const SECURE_REMOTE_PROTOCOL = "synara-remote-e2ee-v1";
export const SECURE_REMOTE_WS_QUERY_PARAM = "secure";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const KEY_LENGTH = 32;
const NONCE_PREFIX_LENGTH = 4;
const NONCE_LENGTH = 12;

export interface SecureRemotePairingServerIdentity {
  readonly protocol: typeof SECURE_REMOTE_PROTOCOL;
  readonly serverDeviceId: string;
  readonly serverIdentityPublicKey: string;
}

export interface SecureRemotePairingPayload extends SecureRemotePairingServerIdentity {
  readonly v: 1;
  readonly origin: string;
  readonly credential: string;
  readonly expiresAt: string;
}

export interface SecureRemoteIdentity {
  readonly deviceId: string;
  readonly identitySecretKey: string;
  readonly identityPublicKey: string;
}

export interface SecureClientHello {
  readonly type: "synara.secure.clientHello";
  readonly v: 1;
  readonly protocol: typeof SECURE_REMOTE_PROTOCOL;
  readonly clientDeviceId: string;
  readonly clientIdentityPublicKey: string;
  readonly clientEphemeralPublicKey: string;
  readonly clientNonce: string;
  readonly expectedServerDeviceId: string;
  readonly expectedServerIdentityPublicKey: string;
}

export interface SecureServerHello {
  readonly type: "synara.secure.serverHello";
  readonly v: 1;
  readonly protocol: typeof SECURE_REMOTE_PROTOCOL;
  readonly serverDeviceId: string;
  readonly serverIdentityPublicKey: string;
  readonly serverEphemeralPublicKey: string;
  readonly serverNonce: string;
  readonly serverSignature: string;
}

export interface SecureClientAuth {
  readonly type: "synara.secure.clientAuth";
  readonly v: 1;
  readonly protocol: typeof SECURE_REMOTE_PROTOCOL;
  readonly clientSignature: string;
}

export interface SecureFrame {
  readonly type: "synara.secure.frame";
  readonly v: 1;
  readonly counter: string;
  readonly data: string;
}

export interface PendingSecureClientHandshake {
  readonly hello: SecureClientHello;
  readonly clientEphemeralSecretKey: Uint8Array;
}

export interface PendingSecureServerHandshake {
  readonly hello: SecureServerHello;
  readonly serverEphemeralSecretKey: Uint8Array;
}

export interface SecureTransportSession {
  readonly role: "client" | "server";
  readonly transcriptHash: Uint8Array;
  sendCounter: bigint;
  receiveCounter: bigint;
  readonly sendKey: Uint8Array;
  readonly receiveKey: Uint8Array;
  readonly sendNoncePrefix: Uint8Array;
  readonly receiveNoncePrefix: Uint8Array;
}

function toBytes(value: string): Uint8Array {
  return textEncoder.encode(value);
}

function fromBytes(value: Uint8Array): string {
  return textDecoder.decode(value);
}

function assertByteLength(value: Uint8Array, length: number, label: string): Uint8Array {
  if (value.byteLength !== length) {
    throw new Error(`${label} must be ${length} bytes.`);
  }
  return value;
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof btoa === "function") {
    let binary = "";
    for (let offset = 0; offset < bytes.byteLength; offset += 0x8000) {
      const chunk = bytes.subarray(offset, offset + 0x8000);
      binary += String.fromCharCode(...chunk);
    }
    return btoa(binary);
  }
  return Buffer.from(bytes).toString("base64");
}

function base64ToBytes(value: string): Uint8Array {
  if (typeof atob === "function") {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }
  return new Uint8Array(Buffer.from(value, "base64"));
}

export function base64UrlEncodeBytes(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function base64UrlDecodeBytes(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = `${normalized}${"=".repeat((4 - (normalized.length % 4)) % 4)}`;
  return base64ToBytes(padded);
}

export function generateSecureRemoteIdentity(): SecureRemoteIdentity {
  return identityFromSecretKey(ed25519.utils.randomSecretKey());
}

export function identityFromSecretKey(secretKey: Uint8Array): SecureRemoteIdentity {
  const normalizedSecretKey = assertByteLength(secretKey, KEY_LENGTH, "identity secret key");
  const publicKey = ed25519.getPublicKey(normalizedSecretKey);
  return {
    deviceId: base64UrlEncodeBytes(sha256(publicKey).subarray(0, 16)),
    identitySecretKey: base64UrlEncodeBytes(normalizedSecretKey),
    identityPublicKey: base64UrlEncodeBytes(publicKey),
  };
}

export function decodeIdentitySecretKey(identity: SecureRemoteIdentity): Uint8Array {
  return assertByteLength(
    base64UrlDecodeBytes(identity.identitySecretKey),
    KEY_LENGTH,
    "identity secret key",
  );
}

export function decodeIdentityPublicKey(publicKey: string): Uint8Array {
  return assertByteLength(base64UrlDecodeBytes(publicKey), KEY_LENGTH, "identity public key");
}

export function encodeSecurePairingPayload(payload: SecureRemotePairingPayload): string {
  return base64UrlEncodeBytes(toBytes(JSON.stringify(payload)));
}

export function decodeSecurePairingPayload(encoded: string): SecureRemotePairingPayload {
  const payload = JSON.parse(fromBytes(base64UrlDecodeBytes(encoded))) as Partial<SecureRemotePairingPayload>;
  if (
    payload.v !== 1 ||
    payload.protocol !== SECURE_REMOTE_PROTOCOL ||
    typeof payload.origin !== "string" ||
    typeof payload.credential !== "string" ||
    typeof payload.expiresAt !== "string" ||
    typeof payload.serverDeviceId !== "string" ||
    typeof payload.serverIdentityPublicKey !== "string"
  ) {
    throw new Error("Invalid secure pairing payload.");
  }
  decodeIdentityPublicKey(payload.serverIdentityPublicKey);
  return {
    v: 1,
    protocol: SECURE_REMOTE_PROTOCOL,
    origin: payload.origin,
    credential: payload.credential,
    expiresAt: payload.expiresAt,
    serverDeviceId: payload.serverDeviceId,
    serverIdentityPublicKey: payload.serverIdentityPublicKey,
  };
}

export function buildSecurePairingUrl(
  origin: string,
  payload: SecureRemotePairingPayload,
): string {
  const url = new URL(origin);
  url.pathname = "/pair";
  url.search = "";
  url.hash = new URLSearchParams([
    ["token", payload.credential],
    ["secure", encodeSecurePairingPayload(payload)],
  ]).toString();
  return url.toString();
}

export function createSecurePairingPayload(input: {
  readonly origin: string;
  readonly credential: string;
  readonly expiresAt: string;
  readonly serverIdentity: SecureRemotePairingServerIdentity;
}): SecureRemotePairingPayload {
  return {
    v: 1,
    origin: input.origin,
    credential: input.credential,
    expiresAt: input.expiresAt,
    protocol: SECURE_REMOTE_PROTOCOL,
    serverDeviceId: input.serverIdentity.serverDeviceId,
    serverIdentityPublicKey: input.serverIdentity.serverIdentityPublicKey,
  };
}

export function createClientHello(input: {
  readonly clientIdentity: SecureRemoteIdentity;
  readonly expectedServer: SecureRemotePairingServerIdentity;
}): PendingSecureClientHandshake {
  const ephemeral = x25519.keygen();
  return {
    hello: {
      type: "synara.secure.clientHello",
      v: 1,
      protocol: SECURE_REMOTE_PROTOCOL,
      clientDeviceId: input.clientIdentity.deviceId,
      clientIdentityPublicKey: input.clientIdentity.identityPublicKey,
      clientEphemeralPublicKey: base64UrlEncodeBytes(ephemeral.publicKey),
      clientNonce: base64UrlEncodeBytes(crypto.getRandomValues(new Uint8Array(16))),
      expectedServerDeviceId: input.expectedServer.serverDeviceId,
      expectedServerIdentityPublicKey: input.expectedServer.serverIdentityPublicKey,
    },
    clientEphemeralSecretKey: ephemeral.secretKey,
  };
}

export function createServerHello(input: {
  readonly clientHello: SecureClientHello;
  readonly serverIdentity: SecureRemoteIdentity;
}): PendingSecureServerHandshake {
  assertValidClientHello(input.clientHello);
  if (
    input.clientHello.expectedServerDeviceId !== input.serverIdentity.deviceId ||
    input.clientHello.expectedServerIdentityPublicKey !== input.serverIdentity.identityPublicKey
  ) {
    throw new Error("Client expected a different server identity.");
  }

  const ephemeral = x25519.keygen();
  const unsignedHello = {
    type: "synara.secure.serverHello" as const,
    v: 1 as const,
    protocol: SECURE_REMOTE_PROTOCOL,
    serverDeviceId: input.serverIdentity.deviceId,
    serverIdentityPublicKey: input.serverIdentity.identityPublicKey,
    serverEphemeralPublicKey: base64UrlEncodeBytes(ephemeral.publicKey),
    serverNonce: base64UrlEncodeBytes(crypto.getRandomValues(new Uint8Array(16))),
  };
  const transcript = encodeHandshakeTranscript(input.clientHello, unsignedHello);
  const signature = ed25519.sign(toBytes(transcript), decodeIdentitySecretKey(input.serverIdentity));
  return {
    hello: {
      ...unsignedHello,
      serverSignature: base64UrlEncodeBytes(signature),
    },
    serverEphemeralSecretKey: ephemeral.secretKey,
  };
}

export function createClientAuth(input: {
  readonly clientHello: SecureClientHello;
  readonly serverHello: SecureServerHello;
  readonly clientIdentity: SecureRemoteIdentity;
}): SecureClientAuth {
  const authTranscript = encodeClientAuthTranscript(input.clientHello, input.serverHello);
  const signature = ed25519.sign(toBytes(authTranscript), decodeIdentitySecretKey(input.clientIdentity));
  return {
    type: "synara.secure.clientAuth",
    v: 1,
    protocol: SECURE_REMOTE_PROTOCOL,
    clientSignature: base64UrlEncodeBytes(signature),
  };
}

export function verifyServerHello(input: {
  readonly clientHello: SecureClientHello;
  readonly serverHello: SecureServerHello;
  readonly expectedServer: SecureRemotePairingServerIdentity;
}): string {
  assertValidClientHello(input.clientHello);
  assertValidServerHello(input.serverHello);
  if (
    input.serverHello.serverDeviceId !== input.expectedServer.serverDeviceId ||
    input.serverHello.serverIdentityPublicKey !== input.expectedServer.serverIdentityPublicKey
  ) {
    throw new Error("Server identity does not match the pairing record.");
  }
  const transcript = encodeHandshakeTranscript(input.clientHello, omitServerSignature(input.serverHello));
  const ok = ed25519.verify(
    base64UrlDecodeBytes(input.serverHello.serverSignature),
    toBytes(transcript),
    decodeIdentityPublicKey(input.serverHello.serverIdentityPublicKey),
  );
  if (!ok) {
    throw new Error("Invalid server handshake signature.");
  }
  return transcript;
}

export function verifyClientAuth(input: {
  readonly clientHello: SecureClientHello;
  readonly serverHello: SecureServerHello;
  readonly clientAuth: SecureClientAuth;
  readonly expectedClientIdentityPublicKey: string;
}): void {
  assertValidClientHello(input.clientHello);
  assertValidServerHello(input.serverHello);
  if (
    input.clientAuth.type !== "synara.secure.clientAuth" ||
    input.clientAuth.v !== 1 ||
    input.clientAuth.protocol !== SECURE_REMOTE_PROTOCOL
  ) {
    throw new Error("Invalid client auth message.");
  }
  if (input.clientHello.clientIdentityPublicKey !== input.expectedClientIdentityPublicKey) {
    throw new Error("Client identity does not match the authenticated session.");
  }
  const ok = ed25519.verify(
    base64UrlDecodeBytes(input.clientAuth.clientSignature),
    toBytes(encodeClientAuthTranscript(input.clientHello, input.serverHello)),
    decodeIdentityPublicKey(input.expectedClientIdentityPublicKey),
  );
  if (!ok) {
    throw new Error("Invalid client handshake signature.");
  }
}

export function deriveClientSession(input: {
  readonly clientHello: SecureClientHello;
  readonly serverHello: SecureServerHello;
  readonly clientEphemeralSecretKey: Uint8Array;
  readonly expectedServer: SecureRemotePairingServerIdentity;
}): SecureTransportSession {
  const transcript = verifyServerHello({
    clientHello: input.clientHello,
    serverHello: input.serverHello,
    expectedServer: input.expectedServer,
  });
  return deriveSession({
    role: "client",
    sharedSecret: x25519.getSharedSecret(
      input.clientEphemeralSecretKey,
      base64UrlDecodeBytes(input.serverHello.serverEphemeralPublicKey),
    ),
    transcript,
  });
}

export function deriveServerSession(input: {
  readonly clientHello: SecureClientHello;
  readonly serverHello: SecureServerHello;
  readonly serverEphemeralSecretKey: Uint8Array;
}): SecureTransportSession {
  return deriveSession({
    role: "server",
    sharedSecret: x25519.getSharedSecret(
      input.serverEphemeralSecretKey,
      base64UrlDecodeBytes(input.clientHello.clientEphemeralPublicKey),
    ),
    transcript: encodeHandshakeTranscript(input.clientHello, omitServerSignature(input.serverHello)),
  });
}

export function encryptSecureFrame(session: SecureTransportSession, plaintext: Uint8Array): SecureFrame {
  const counter = session.sendCounter;
  session.sendCounter += 1n;
  const nonce = makeNonce(session.sendNoncePrefix, counter);
  const ciphertext = gcm(session.sendKey, nonce, makeFrameAad(session, "send", counter)).encrypt(
    plaintext,
  );
  return {
    type: "synara.secure.frame",
    v: 1,
    counter: counter.toString(),
    data: base64UrlEncodeBytes(ciphertext),
  };
}

export function decryptSecureFrame(session: SecureTransportSession, frame: SecureFrame): Uint8Array {
  if (frame.type !== "synara.secure.frame" || frame.v !== 1) {
    throw new Error("Invalid secure frame.");
  }
  const counter = BigInt(frame.counter);
  if (counter !== session.receiveCounter) {
    throw new Error("Secure frame replay or out-of-order counter detected.");
  }
  const nonce = makeNonce(session.receiveNoncePrefix, counter);
  const plaintext = gcm(
    session.receiveKey,
    nonce,
    makeFrameAad(session, "receive", counter),
  ).decrypt(base64UrlDecodeBytes(frame.data));
  session.receiveCounter += 1n;
  return plaintext;
}

export function parseSecureControlMessage(data: string | Uint8Array): unknown {
  const raw = typeof data === "string" ? data : fromBytes(data);
  return JSON.parse(raw) as unknown;
}

export function serializeSecureControlMessage(message: unknown): string {
  return JSON.stringify(message);
}

function deriveSession(input: {
  readonly role: "client" | "server";
  readonly sharedSecret: Uint8Array;
  readonly transcript: string;
}): SecureTransportSession {
  const transcriptHash = sha256(toBytes(input.transcript));
  const material = hkdf(
    sha256,
    input.sharedSecret,
    transcriptHash,
    toBytes(`${SECURE_REMOTE_PROTOCOL}:transport`),
    KEY_LENGTH * 2 + NONCE_PREFIX_LENGTH * 2,
  );
  const clientToServerKey = material.subarray(0, KEY_LENGTH);
  const serverToClientKey = material.subarray(KEY_LENGTH, KEY_LENGTH * 2);
  const clientToServerNoncePrefix = material.subarray(
    KEY_LENGTH * 2,
    KEY_LENGTH * 2 + NONCE_PREFIX_LENGTH,
  );
  const serverToClientNoncePrefix = material.subarray(KEY_LENGTH * 2 + NONCE_PREFIX_LENGTH);

  return {
    role: input.role,
    transcriptHash,
    sendCounter: 0n,
    receiveCounter: 0n,
    sendKey: input.role === "client" ? clientToServerKey : serverToClientKey,
    receiveKey: input.role === "client" ? serverToClientKey : clientToServerKey,
    sendNoncePrefix:
      input.role === "client" ? clientToServerNoncePrefix : serverToClientNoncePrefix,
    receiveNoncePrefix:
      input.role === "client" ? serverToClientNoncePrefix : clientToServerNoncePrefix,
  };
}

function makeNonce(prefix: Uint8Array, counter: bigint): Uint8Array {
  const nonce = new Uint8Array(NONCE_LENGTH);
  nonce.set(assertByteLength(prefix, NONCE_PREFIX_LENGTH, "nonce prefix"), 0);
  new DataView(nonce.buffer).setBigUint64(4, counter, false);
  return nonce;
}

function makeFrameAad(
  session: SecureTransportSession,
  mode: "send" | "receive",
  counter: bigint,
): Uint8Array {
  const direction =
    session.role === "client"
      ? mode === "send"
        ? "client-to-server"
        : "server-to-client"
      : mode === "send"
        ? "server-to-client"
        : "client-to-server";
  return toBytes(
    `${SECURE_REMOTE_PROTOCOL}:${direction}:${base64UrlEncodeBytes(session.transcriptHash)}:${counter}`,
  );
}

function encodeHandshakeTranscript(
  clientHello: SecureClientHello,
  serverHello: Omit<SecureServerHello, "serverSignature">,
): string {
  return JSON.stringify({
    protocol: SECURE_REMOTE_PROTOCOL,
    clientHello: {
      type: clientHello.type,
      v: clientHello.v,
      protocol: clientHello.protocol,
      clientDeviceId: clientHello.clientDeviceId,
      clientIdentityPublicKey: clientHello.clientIdentityPublicKey,
      clientEphemeralPublicKey: clientHello.clientEphemeralPublicKey,
      clientNonce: clientHello.clientNonce,
      expectedServerDeviceId: clientHello.expectedServerDeviceId,
      expectedServerIdentityPublicKey: clientHello.expectedServerIdentityPublicKey,
    },
    serverHello: {
      type: serverHello.type,
      v: serverHello.v,
      protocol: serverHello.protocol,
      serverDeviceId: serverHello.serverDeviceId,
      serverIdentityPublicKey: serverHello.serverIdentityPublicKey,
      serverEphemeralPublicKey: serverHello.serverEphemeralPublicKey,
      serverNonce: serverHello.serverNonce,
    },
  });
}

function encodeClientAuthTranscript(
  clientHello: SecureClientHello,
  serverHello: SecureServerHello,
): string {
  return JSON.stringify({
    protocol: SECURE_REMOTE_PROTOCOL,
    handshakeTranscript: encodeHandshakeTranscript(clientHello, omitServerSignature(serverHello)),
    serverSignature: serverHello.serverSignature,
  });
}

function omitServerSignature(serverHello: SecureServerHello): Omit<SecureServerHello, "serverSignature"> {
  return {
    type: serverHello.type,
    v: serverHello.v,
    protocol: serverHello.protocol,
    serverDeviceId: serverHello.serverDeviceId,
    serverIdentityPublicKey: serverHello.serverIdentityPublicKey,
    serverEphemeralPublicKey: serverHello.serverEphemeralPublicKey,
    serverNonce: serverHello.serverNonce,
  };
}

function assertValidClientHello(value: SecureClientHello): void {
  if (
    value.type !== "synara.secure.clientHello" ||
    value.v !== 1 ||
    value.protocol !== SECURE_REMOTE_PROTOCOL
  ) {
    throw new Error("Invalid client hello.");
  }
  decodeIdentityPublicKey(value.clientIdentityPublicKey);
  assertByteLength(
    base64UrlDecodeBytes(value.clientEphemeralPublicKey),
    KEY_LENGTH,
    "client ephemeral public key",
  );
  assertByteLength(base64UrlDecodeBytes(value.clientNonce), 16, "client nonce");
}

function assertValidServerHello(value: SecureServerHello): void {
  if (
    value.type !== "synara.secure.serverHello" ||
    value.v !== 1 ||
    value.protocol !== SECURE_REMOTE_PROTOCOL
  ) {
    throw new Error("Invalid server hello.");
  }
  decodeIdentityPublicKey(value.serverIdentityPublicKey);
  assertByteLength(
    base64UrlDecodeBytes(value.serverEphemeralPublicKey),
    KEY_LENGTH,
    "server ephemeral public key",
  );
  assertByteLength(base64UrlDecodeBytes(value.serverNonce), 16, "server nonce");
  assertByteLength(base64UrlDecodeBytes(value.serverSignature), 64, "server signature");
}
