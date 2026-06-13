// FILE: wsUrlSource.ts
// Purpose: Selects usable WebSocket endpoint hints for local, desktop, and proxied remote web.
// Layer: Web transport utility

function normalizeHostname(hostname: string): string {
  return hostname.trim().replace(/^\[(.*)\]$/, "$1").toLowerCase();
}

export function isLoopbackHostname(hostname: string | null | undefined): boolean {
  if (!hostname) return false;
  const normalized = normalizeHostname(hostname);
  return (
    normalized === "localhost" ||
    normalized === "::1" ||
    normalized === "0:0:0:0:0:0:0:1" ||
    normalized.startsWith("127.")
  );
}

function readPageHostname(): string | null {
  if (typeof window === "undefined") return null;
  const location = window.location;
  if (!location) return null;
  if (typeof location.hostname === "string" && location.hostname.length > 0) {
    return location.hostname;
  }
  if (typeof location.href === "string" && location.href.length > 0) {
    try {
      return new URL(location.href).hostname;
    } catch {
      return null;
    }
  }
  return null;
}

function readUrlHostname(rawUrl: string): string | null {
  try {
    return new URL(rawUrl).hostname;
  } catch {
    return null;
  }
}

export function resolveUsableEnvWsUrl(envWsUrl: string | undefined): string | null {
  if (typeof envWsUrl !== "string" || envWsUrl.length === 0) {
    return null;
  }

  const envHostname = readUrlHostname(envWsUrl);
  const pageHostname = readPageHostname();
  if (
    envHostname &&
    pageHostname &&
    isLoopbackHostname(envHostname) &&
    !isLoopbackHostname(pageHostname)
  ) {
    return null;
  }

  return envWsUrl;
}
