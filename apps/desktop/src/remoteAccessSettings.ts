import * as FS from "node:fs";
import * as Path from "node:path";

import {
  DEFAULT_SERVER_SETTINGS,
  ServerSettings,
  type RemoteAccessServerSettings,
} from "@t3tools/contracts";
import { Schema } from "effect";

const SETTINGS_FILE_NAME = "settings.json";

export function resolveDesktopSettingsPath(stateDir: string): string {
  return Path.join(stateDir, SETTINGS_FILE_NAME);
}

export function readRemoteAccessSettingsFromDisk(stateDir: string): RemoteAccessServerSettings {
  const settingsPath = resolveDesktopSettingsPath(stateDir);
  if (!FS.existsSync(settingsPath)) {
    return DEFAULT_SERVER_SETTINGS.remoteAccess;
  }

  try {
    const raw = FS.readFileSync(settingsPath, "utf8");
    const decoded = Schema.decodeUnknownSync(ServerSettings)(JSON.parse(raw) as unknown);
    return decoded.remoteAccess;
  } catch {
    return DEFAULT_SERVER_SETTINGS.remoteAccess;
  }
}
