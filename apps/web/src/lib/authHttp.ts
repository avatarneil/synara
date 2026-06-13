// FILE: authHttp.ts
// Purpose: HTTP-only auth helpers used before the WebSocket transport is authenticated.
// Layer: Web auth utility

import { resolveWsHttpUrl } from "./wsHttpUrl";
import { resolveUsableEnvWsUrl } from "./wsUrlSource";

function readTokenParam(rawUrl: string): string | null {
  try {
    const url = new URL(rawUrl);
    const token = url.searchParams.get("token")?.trim();
    if (token) return token;
    const wsToken = url.searchParams.get("wsToken")?.trim();
    return wsToken && wsToken.length > 0 ? wsToken : null;
  } catch {
    return null;
  }
}

export function readPageLegacyAuthToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    const pageUrl = new URL(window.location.href);
    const fromSearch = pageUrl.searchParams.get("token")?.trim();
    if (fromSearch) return fromSearch;
    const fromHash = new URLSearchParams(pageUrl.hash.slice(1)).get("token")?.trim();
    return fromHash && fromHash.length > 0 ? fromHash : null;
  } catch {
    return null;
  }
}

export function hasAmbientServerCredential(): boolean {
  if (typeof window === "undefined") return false;
  if (readPageLegacyAuthToken()) return true;

  const bridgeWsUrl = window.desktopBridge?.getWsUrl?.();
  if (typeof bridgeWsUrl === "string" && readTokenParam(bridgeWsUrl)) {
    return true;
  }

  const envWsUrl = resolveUsableEnvWsUrl(import.meta.env.VITE_WS_URL as string | undefined);
  return typeof envWsUrl === "string" && Boolean(readTokenParam(envWsUrl));
}

export async function requestAuthJson<T>(
  path: string,
  options: {
    readonly method?: "GET" | "POST";
    readonly body?: unknown;
  } = {},
): Promise<T> {
  const hasBody = options.body !== undefined;
  const response = await fetch(resolveWsHttpUrl(path), {
    method: options.method ?? "GET",
    credentials: "same-origin",
    ...(hasBody
      ? {
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(options.body),
        }
      : {}),
  });
  const payload = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    const message =
      payload &&
      typeof payload === "object" &&
      "error" in payload &&
      typeof payload.error === "string"
        ? payload.error
        : `Auth request failed with status ${response.status}`;
    throw new Error(message);
  }
  return payload as T;
}
