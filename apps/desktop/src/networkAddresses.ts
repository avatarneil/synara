import * as ChildProcess from "node:child_process";
import * as OS from "node:os";

export function resolveTailnetIpv4(): string | null {
  try {
    const output = ChildProcess.execFileSync("tailscale", ["ip", "-4"], {
      encoding: "utf8",
      timeout: 2_000,
    });
    const trimmed = output.trim();
    return trimmed.length > 0 ? trimmed : null;
  } catch {
    return null;
  }
}

export function listLanIpv4Addresses(): ReadonlyArray<string> {
  const addresses = new Set<string>();
  const interfaces = OS.networkInterfaces();
  for (const entries of Object.values(interfaces)) {
    if (!entries) continue;
    for (const entry of entries) {
      if (entry.family !== "IPv4" || entry.internal) continue;
      const address = entry.address.trim();
      if (address.length > 0) {
        addresses.add(address);
      }
    }
  }
  return [...addresses];
}
