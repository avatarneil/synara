// FILE: wsHttpUrl.ts
// Purpose: Resolves server HTTP URLs from the active WebSocket bridge so desktop <img>/download
// requests carry the same legacy startup token already used for the WS connection.
// Layer: Web utility
// Exports: resolveWsHttpUrl, toAttachmentPreviewUrl

import { resolveUsableEnvWsUrl } from "./wsUrlSource";

// Build a fully-qualified HTTP URL for `rawPath` against the same server the WS connection uses.
// On desktop the page is served from a custom protocol scheme, so <img>/<a download> with a
// relative path never reaches the server. We mirror the WS host and forward the legacy token
// query param so authenticated GET routes (attachments, local-image, …) can authorize the
// request without touching cookies.
function resolveBrowserOrigin(): string | null {
  const location = window.location;
  if (!location) {
    return null;
  }
  if (typeof location.origin === "string" && location.origin.length > 0) {
    return location.origin;
  }
  if (typeof location.protocol === "string" && typeof location.hostname === "string") {
    const port =
      typeof location.port === "string" && location.port.length > 0 ? `:${location.port}` : "";
    return `${location.protocol}//${location.hostname}${port}`;
  }
  return null;
}

export function resolveWsHttpUrl(rawPath: string): string {
  if (typeof window === "undefined") return rawPath;
  const bridgeWsUrl = window.desktopBridge?.getWsUrl?.();
  const envWsUrl = resolveUsableEnvWsUrl(import.meta.env.VITE_WS_URL as string | undefined);
  const wsCandidate =
    typeof bridgeWsUrl === "string" && bridgeWsUrl.length > 0
      ? bridgeWsUrl
      : envWsUrl
        ? envWsUrl
        : null;
  const browserOrigin = resolveBrowserOrigin();
  if (!wsCandidate) return browserOrigin ? new URL(rawPath, browserOrigin).toString() : rawPath;
  try {
    const wsUrl = new URL(wsCandidate);
    const protocol =
      wsUrl.protocol === "wss:" ? "https:" : wsUrl.protocol === "ws:" ? "http:" : wsUrl.protocol;
    const httpUrl = new URL(rawPath, `${protocol}//${wsUrl.host}`);
    const legacyToken = wsUrl.searchParams.get("token");
    if (legacyToken && !httpUrl.searchParams.has("token")) {
      httpUrl.searchParams.set("token", legacyToken);
    }
    return httpUrl.toString();
  } catch {
    return browserOrigin ? new URL(rawPath, browserOrigin).toString() : rawPath;
  }
}

export function toAttachmentPreviewUrl(rawUrl: string): string {
  if (rawUrl.startsWith("/")) {
    return resolveWsHttpUrl(rawUrl);
  }
  return rawUrl;
}
