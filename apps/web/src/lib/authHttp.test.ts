import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { hasAmbientServerCredential, readPageLegacyAuthToken } from "./authHttp";

function setWindow(input: {
  readonly href?: string;
  readonly desktopBridge?: { readonly getWsUrl?: () => string | null };
}) {
  const href = input.href ?? "http://100.64.0.10:6767/";
  const url = new URL(href);
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: {
        href,
        search: url.search,
        hash: url.hash,
        origin: url.origin,
      },
      desktopBridge: input.desktopBridge,
    },
  });
}

beforeEach(() => {
  vi.stubEnv("VITE_WS_URL", "");
  setWindow({});
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("authHttp", () => {
  it("does not report ambient credentials for a bare remote browser URL", () => {
    expect(readPageLegacyAuthToken()).toBeNull();
    expect(hasAmbientServerCredential()).toBe(false);
  });

  it("reads legacy tokens from the page URL", () => {
    setWindow({ href: "http://100.64.0.10:6767/?token=remote-secret" });

    expect(readPageLegacyAuthToken()).toBe("remote-secret");
    expect(hasAmbientServerCredential()).toBe(true);
  });

  it("detects desktop bridge WebSocket credentials", () => {
    setWindow({
      desktopBridge: {
        getWsUrl: () => "ws://100.64.0.10:6767/?token=desktop-secret",
      },
    });

    expect(hasAmbientServerCredential()).toBe(true);
  });

  it("detects configured WebSocket credentials", () => {
    vi.stubEnv("VITE_WS_URL", "ws://100.64.0.10:6767/?wsToken=paired-token");

    expect(hasAmbientServerCredential()).toBe(true);
  });

  it("ignores loopback WebSocket env credentials on remote browser origins", () => {
    vi.stubEnv("VITE_WS_URL", "ws://[::1]:3773/?token=local-dev-token");
    setWindow({ href: "http://100.64.0.10:6767/" });

    expect(hasAmbientServerCredential()).toBe(false);
  });
});
