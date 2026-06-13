// FILE: secureRemoteIdentity.ts
// Purpose: Loads the persisted server identity used for secure remote pairing.
// Layer: Server auth helpers

import {
  SECURE_REMOTE_PROTOCOL,
  identityFromSecretKey,
  type SecureRemoteIdentity,
  type SecureRemotePairingServerIdentity,
} from "@t3tools/shared/secureRemote";
import { Effect } from "effect";

import { ServerSecretStore } from "./Services/ServerSecretStore";

const SECURE_REMOTE_IDENTITY_SECRET_NAME = "remote-identity-ed25519";
const IDENTITY_SECRET_KEY_BYTES = 32;

export const getSecureRemoteIdentity = Effect.gen(function* () {
  const secretStore = yield* ServerSecretStore;
  const secretKey = yield* secretStore.getOrCreateRandom(
    SECURE_REMOTE_IDENTITY_SECRET_NAME,
    IDENTITY_SECRET_KEY_BYTES,
  );
  return identityFromSecretKey(secretKey) satisfies SecureRemoteIdentity;
});

export const getSecureRemotePairingServerIdentity = getSecureRemoteIdentity.pipe(
  Effect.map(
    (identity) =>
      ({
        protocol: SECURE_REMOTE_PROTOCOL,
        serverDeviceId: identity.deviceId,
        serverIdentityPublicKey: identity.identityPublicKey,
      }) satisfies SecureRemotePairingServerIdentity,
  ),
);
