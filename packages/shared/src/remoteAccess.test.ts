import { describe, expect, it } from "vitest";

import {
  buildPairingUrl,
  buildReachableHttpUrls,
  isRemoteAccessReachable,
  resolveRemoteAccessBindHost,
} from "./remoteAccess";

describe("remoteAccess", () => {
  it("keeps loopback bind when remote access is disabled", () => {
    expect(
      resolveRemoteAccessBindHost({
        enabled: false,
        bindMode: "tailnet",
        customHost: "",
        port: null,
      }),
    ).toBe("127.0.0.1");
  });

  it("resolves tailnet and custom bind hosts when enabled", () => {
    expect(
      resolveRemoteAccessBindHost(
        {
          enabled: true,
          bindMode: "tailnet",
          customHost: "",
          port: null,
        },
        { tailnetIpv4: "100.64.0.10" },
      ),
    ).toBe("100.64.0.10");

    expect(
      resolveRemoteAccessBindHost({
        enabled: true,
        bindMode: "custom",
        customHost: "192.168.1.42",
        port: 3773,
      }),
    ).toBe("192.168.1.42");
  });

  it("builds reachable URLs for remote bind hosts", () => {
    expect(
      buildReachableHttpUrls({
        bindHost: "100.64.0.10",
        port: 3773,
        tailnetIpv4: "100.64.0.10",
        lanIpv4Addresses: ["192.168.1.42"],
      }),
    ).toEqual([
      "http://127.0.0.1:3773",
      "http://100.64.0.10:3773",
      "http://192.168.1.42:3773",
    ]);
  });

  it("builds pairing URLs with hash tokens", () => {
    expect(buildPairingUrl("http://100.64.0.10:3773", "ABCD2345")).toBe(
      "http://100.64.0.10:3773/pair#token=ABCD2345",
    );
  });

  it("detects remote reachability from bind host", () => {
    expect(
      isRemoteAccessReachable(
        {
          enabled: true,
          bindMode: "tailnet",
          customHost: "",
          port: null,
        },
        "100.64.0.10",
      ),
    ).toBe(true);
    expect(
      isRemoteAccessReachable(
        {
          enabled: true,
          bindMode: "loopback",
          customHost: "",
          port: null,
        },
        "127.0.0.1",
      ),
    ).toBe(false);
  });
});
