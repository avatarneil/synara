import type { DesktopNetworkRuntimeInfo } from "@t3tools/contracts";

export const DESKTOP_RUNTIME_INFO_CHANNEL = "desktop:get-network-runtime-info";
export const DESKTOP_RESTART_BACKEND_CHANNEL = "desktop:restart-backend";

export function buildDesktopNetworkRuntimeInfo(input: {
  readonly httpOrigin: string;
  readonly wsUrl: string;
  readonly bindHost: string;
  readonly port: number;
  readonly remoteEnabled: boolean;
  readonly remoteReachable: boolean;
  readonly reachableUrls: ReadonlyArray<string>;
}): DesktopNetworkRuntimeInfo {
  return {
    httpOrigin: input.httpOrigin,
    wsUrl: input.wsUrl,
    bindHost: input.bindHost,
    port: input.port,
    remoteEnabled: input.remoteEnabled,
    remoteReachable: input.remoteReachable,
    reachableUrls: input.reachableUrls,
  };
}
