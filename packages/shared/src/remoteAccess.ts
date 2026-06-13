import type { RemoteAccessServerSettings } from "@t3tools/contracts";

export const isWildcardHost = (host: string | undefined): boolean =>
  host === "0.0.0.0" || host === "::" || host === "[::]";

export const isLoopbackHost = (host: string | undefined): boolean => {
  if (!host) return true;
  const normalized = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
};

export const formatHostForUrl = (host: string): string =>
  host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;

export function resolveRemoteAccessBindHost(
  remoteAccess: RemoteAccessServerSettings,
  options?: { readonly tailnetIpv4?: string | null },
): string {
  if (!remoteAccess.enabled) {
    return "127.0.0.1";
  }

  switch (remoteAccess.bindMode) {
    case "all-interfaces":
      return "0.0.0.0";
    case "tailnet": {
      const tailnetIpv4 = options?.tailnetIpv4?.trim();
      return tailnetIpv4 && tailnetIpv4.length > 0 ? tailnetIpv4 : "127.0.0.1";
    }
    case "custom": {
      const customHost = remoteAccess.customHost.trim();
      return customHost.length > 0 ? customHost : "127.0.0.1";
    }
    case "loopback":
    default:
      return "127.0.0.1";
  }
}

export function isRemoteAccessReachable(
  remoteAccess: RemoteAccessServerSettings,
  bindHost: string,
): boolean {
  return remoteAccess.enabled && !isLoopbackHost(bindHost);
}

export function buildReachableHttpUrls(input: {
  readonly bindHost: string;
  readonly port: number;
  readonly tailnetIpv4?: string | null;
  readonly lanIpv4Addresses?: ReadonlyArray<string>;
}): ReadonlyArray<string> {
  const urls = new Set<string>();
  const add = (host: string | undefined) => {
    if (!host || host.trim().length === 0) return;
    urls.add(`http://${formatHostForUrl(host.trim())}:${input.port}`);
  };

  add("127.0.0.1");

  if (isLoopbackHost(input.bindHost)) {
    return [...urls];
  }

  if (!isWildcardHost(input.bindHost)) {
    add(input.bindHost);
  }

  add(input.tailnetIpv4 ?? undefined);
  for (const lanAddress of input.lanIpv4Addresses ?? []) {
    add(lanAddress);
  }

  return [...urls];
}

export function buildPairingUrl(origin: string, credential: string): string {
  const url = new URL(origin);
  url.pathname = "/pair";
  url.search = "";
  url.hash = new URLSearchParams([["token", credential]]).toString();
  return url.toString();
}
