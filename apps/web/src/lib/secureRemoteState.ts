// FILE: secureRemoteState.ts
// Purpose: Stores browser-side secure remote identity and trusted server records.
// Layer: Web auth utility

import {
  SECURE_REMOTE_PROTOCOL,
  generateSecureRemoteIdentity,
  type SecureRemoteIdentity,
  type SecureRemotePairingPayload,
  type SecureRemotePairingServerIdentity,
} from "@t3tools/shared/secureRemote";

const CLIENT_IDENTITY_STORAGE_KEY = "synara.secureRemote.clientIdentity.v1";
const TRUSTED_SERVERS_STORAGE_KEY = "synara.secureRemote.trustedServers.v1";

export interface TrustedSecureRemoteServer extends SecureRemotePairingServerIdentity {
  readonly origin: string;
  readonly pairedAt: string;
}

function readJson<T>(key: string): T | null {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

function writeJson(key: string, value: unknown): void {
  window.localStorage.setItem(key, JSON.stringify(value));
}

export function getOrCreateSecureRemoteClientIdentity(): SecureRemoteIdentity {
  const existing = readJson<SecureRemoteIdentity>(CLIENT_IDENTITY_STORAGE_KEY);
  if (
    existing?.deviceId &&
    existing.identitySecretKey &&
    existing.identityPublicKey
  ) {
    return existing;
  }
  const generated = generateSecureRemoteIdentity();
  writeJson(CLIENT_IDENTITY_STORAGE_KEY, generated);
  return generated;
}

export function saveTrustedSecureRemoteServer(
  payload: SecureRemotePairingPayload,
): TrustedSecureRemoteServer {
  const trustedServer: TrustedSecureRemoteServer = {
    protocol: SECURE_REMOTE_PROTOCOL,
    origin: new URL(payload.origin).origin,
    serverDeviceId: payload.serverDeviceId,
    serverIdentityPublicKey: payload.serverIdentityPublicKey,
    pairedAt: new Date().toISOString(),
  };
  const servers = readTrustedSecureRemoteServers();
  const next = [
    trustedServer,
    ...servers.filter(
      (server) =>
        server.origin !== trustedServer.origin ||
        server.serverDeviceId !== trustedServer.serverDeviceId,
    ),
  ];
  writeJson(TRUSTED_SERVERS_STORAGE_KEY, next);
  return trustedServer;
}

export function readTrustedSecureRemoteServers(): TrustedSecureRemoteServer[] {
  const servers = readJson<TrustedSecureRemoteServer[]>(TRUSTED_SERVERS_STORAGE_KEY);
  if (!Array.isArray(servers)) return [];
  return servers.filter(
    (server) =>
      server.protocol === SECURE_REMOTE_PROTOCOL &&
      typeof server.origin === "string" &&
      typeof server.serverDeviceId === "string" &&
      typeof server.serverIdentityPublicKey === "string",
  );
}

export function getTrustedSecureRemoteServerForSocketUrl(
  rawSocketUrl: string,
): TrustedSecureRemoteServer | null {
  let origin: string;
  try {
    const socketUrl = new URL(rawSocketUrl);
    const protocol =
      socketUrl.protocol === "wss:" ? "https:" : socketUrl.protocol === "ws:" ? "http:" : null;
    if (!protocol) return null;
    origin = `${protocol}//${socketUrl.host}`;
  } catch {
    return null;
  }

  return readTrustedSecureRemoteServers().find((server) => server.origin === origin) ?? null;
}
