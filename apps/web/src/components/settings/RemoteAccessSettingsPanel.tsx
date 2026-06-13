// FILE: RemoteAccessSettingsPanel.tsx
// Purpose: Settings panel for desktop remote access — bind host, URLs, pairing links, clients.
// Layer: Settings UI components

import type {
  AuthClientSession,
  RemoteAccessBindMode,
  RemoteAccessServerSettings,
  ServerSettings,
} from "@t3tools/contracts";
import { buildPairingUrl } from "@t3tools/shared/remoteAccess";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { Button } from "~/components/ui/button";
import { SelectItem } from "~/components/ui/select";
import { Switch } from "~/components/ui/switch";
import { toastManager } from "~/components/ui/toast";
import { isElectron } from "~/env";
import { CopyIcon, ExternalLinkIcon } from "~/lib/icons";
import { ensureNativeApi } from "~/nativeApi";
import {
  serverAuthSessionQueryOptions,
  serverQueryKeys,
  serverSettingsQueryOptions,
} from "~/lib/serverReactQuery";
import { DebouncedSettingTextInput } from "./DebouncedSettingTextInput";
import { SettingsSelectControl } from "./SettingControls";
import { SettingsRow, SettingsSection } from "./SettingsPanelPrimitives";

const BIND_MODE_LABELS: Record<RemoteAccessBindMode, string> = {
  loopback: "Localhost only",
  tailnet: "Tailscale (recommended)",
  "all-interfaces": "All network interfaces",
  custom: "Custom IP or host",
};

function pickPairingOrigin(reachableUrls: ReadonlyArray<string>): string {
  const remoteUrl = reachableUrls.find((url) => !url.includes("127.0.0.1"));
  if (remoteUrl) {
    return remoteUrl;
  }
  if (typeof window !== "undefined" && window.location.origin.startsWith("http")) {
    return window.location.origin;
  }
  return reachableUrls[0] ?? "http://127.0.0.1:3773";
}

async function applyRemoteAccessPatch(
  queryClient: ReturnType<typeof useQueryClient>,
  patch: Partial<RemoteAccessServerSettings>,
): Promise<void> {
  const latestSettings = queryClient.getQueryData<ServerSettings>(serverQueryKeys.settings());
  const current = latestSettings?.remoteAccess;
  if (!current) return;

  const nextRemoteAccess = { ...current, ...patch };
  if (latestSettings) {
    queryClient.setQueryData(serverQueryKeys.settings(), {
      ...latestSettings,
      remoteAccess: nextRemoteAccess,
    });
  }

  const api = ensureNativeApi();
  const nextSettings = await api.server.updateSettings({ remoteAccess: patch });
  queryClient.setQueryData(serverQueryKeys.settings(), nextSettings);

  if (window.desktopBridge?.restartBackend) {
    await window.desktopBridge.restartBackend();
  }
}

function formatClientLabel(client: AuthClientSession): string {
  const parts = [
    client.client.label,
    client.client.deviceType,
    client.client.os,
    client.client.browser,
  ].filter((part) => typeof part === "string" && part.trim().length > 0);
  return parts.length > 0 ? parts.join(" · ") : client.subject;
}

export function RemoteAccessSettingsPanel() {
  const queryClient = useQueryClient();
  const serverSettingsQuery = useQuery(serverSettingsQueryOptions());
  const authSessionQuery = useQuery(serverAuthSessionQueryOptions());
  const remoteAccess = serverSettingsQuery.data?.remoteAccess;
  const runtimeInfo =
    typeof window !== "undefined"
      ? (window.desktopBridge?.getNetworkRuntimeInfo?.() ?? null)
      : null;
  const [pairingUrl, setPairingUrl] = useState<string | null>(null);
  const [isApplying, setIsApplying] = useState(false);

  const reachableUrls = useMemo(() => {
    if (runtimeInfo?.reachableUrls?.length) {
      return runtimeInfo.reachableUrls;
    }
    if (typeof window !== "undefined" && window.location.origin.startsWith("http")) {
      return [window.location.origin];
    }
    return [];
  }, [runtimeInfo?.reachableUrls]);

  const remoteActive = remoteAccess?.enabled && (runtimeInfo?.remoteReachable ?? !isElectron);

  const clientsQuery = useQuery({
    queryKey: ["server", "auth", "clients"],
    queryFn: async () => ensureNativeApi().server.listAuthClients(),
    enabled:
      Boolean(remoteActive) && (isElectron || authSessionQuery.data?.role === "owner"),
    refetchInterval: 15_000,
  });

  const createPairingLink = useMutation({
    mutationFn: async () => {
      const issued = await ensureNativeApi().server.createAuthPairingToken({ label: "Phone" });
      const origin = pickPairingOrigin(reachableUrls);
      return buildPairingUrl(origin, issued.credential);
    },
    onSuccess: (url) => {
      setPairingUrl(url);
      toastManager.add({
        type: "success",
        title: "Pairing link created",
        description: "Open this link on your phone within a few minutes.",
      });
    },
    onError: (error) => {
      toastManager.add({
        type: "error",
        title: "Could not create pairing link",
        description: error instanceof Error ? error.message : "Unknown error",
      });
    },
  });

  const revokeClient = useMutation({
    mutationFn: (sessionId: AuthClientSession["sessionId"]) =>
      ensureNativeApi().server.revokeAuthClient({ sessionId }),
    onSuccess: () => {
      void clientsQuery.refetch();
    },
  });

  const patchRemoteAccess = async (patch: Partial<RemoteAccessServerSettings>) => {
    if (isApplying || !remoteAccess) return;
    setIsApplying(true);
    try {
      await applyRemoteAccessPatch(queryClient, patch);
    } catch (error) {
      toastManager.add({
        type: "error",
        title: "Could not update remote access",
        description: error instanceof Error ? error.message : "Unknown error",
      });
      void queryClient.invalidateQueries({ queryKey: serverQueryKeys.settings() });
    } finally {
      setIsApplying(false);
    }
  };

  const copyText = async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toastManager.add({ type: "success", title: `${label} copied` });
    } catch {
      toastManager.add({ type: "error", title: `Could not copy ${label.toLowerCase()}` });
    }
  };

  if (!remoteAccess) {
    return null;
  }

  return (
    <div className="space-y-6">
      <SettingsSection title="Remote access">
        <SettingsRow
          title="Allow remote connections"
          description={
            isElectron
              ? "Share this Synara instance with phones and other devices on your tailnet or LAN. The desktop app keeps hosting the backend."
              : "Remote access is configured by how the server was started (--host, --auth-token)."
          }
          control={
            isElectron ? (
              <Switch
                checked={remoteAccess.enabled}
                disabled={isApplying}
                onCheckedChange={(checked) =>
                  void patchRemoteAccess(
                    checked && remoteAccess.bindMode === "loopback"
                      ? { enabled: true, bindMode: "tailnet" }
                      : { enabled: Boolean(checked) },
                  )
                }
              />
            ) : null
          }
          status={
            runtimeInfo
              ? `Listening on ${runtimeInfo.bindHost}:${runtimeInfo.port}${
                  runtimeInfo.remoteReachable ? " (remote reachable)" : ""
                }`
              : undefined
          }
        />

        {isElectron && remoteAccess.enabled ? (
          <>
            <SettingsRow
              title="Bind address"
              description="Prefer Tailscale so the server is reachable on your private mesh without exposing the public internet."
              control={
                <SettingsSelectControl
                  value={remoteAccess.bindMode}
                  onValueChange={(value) =>
                    void patchRemoteAccess({ bindMode: value as RemoteAccessBindMode })
                  }
                  ariaLabel="Remote bind address"
                  valueContent={BIND_MODE_LABELS[remoteAccess.bindMode]}
                >
                  {(Object.keys(BIND_MODE_LABELS) as RemoteAccessBindMode[]).map((mode) => (
                    <SelectItem hideIndicator key={mode} value={mode}>
                      {BIND_MODE_LABELS[mode]}
                    </SelectItem>
                  ))}
                </SettingsSelectControl>
              }
            />

            {remoteAccess.bindMode === "custom" ? (
              <SettingsRow
                title="Custom host"
                description="Use a specific interface address, such as your Tailnet IP."
                control={
                  <DebouncedSettingTextInput
                    className="w-full sm:w-56"
                    value={remoteAccess.customHost}
                    placeholder="100.x.x.x"
                    disabled={isApplying}
                    onCommit={(customHost) => void patchRemoteAccess({ customHost })}
                  />
                }
              />
            ) : null}

            <SettingsRow
              title="Port"
              description="Leave blank to pick an available port automatically."
              control={
                <DebouncedSettingTextInput
                  className="w-full sm:w-32"
                  value={remoteAccess.port === null ? "" : String(remoteAccess.port)}
                  placeholder="Auto"
                  inputMode="numeric"
                  disabled={isApplying}
                  onCommit={(raw) => {
                    const trimmed = raw.trim();
                    if (trimmed.length === 0) {
                      void patchRemoteAccess({ port: null });
                      return;
                    }
                    const parsed = Number.parseInt(trimmed, 10);
                    if (!Number.isFinite(parsed) || parsed <= 0 || parsed > 65535) {
                      return;
                    }
                    void patchRemoteAccess({ port: parsed });
                  }}
                />
              }
            />
          </>
        ) : null}

        {remoteActive && reachableUrls.length > 0 ? (
          <SettingsRow
            title="Open from another device"
            description="Use one of these URLs in a browser on your phone or another computer."
          >
            <div className="space-y-2 pt-1">
              {reachableUrls.map((url) => (
                <div
                  key={url}
                  className="flex flex-col gap-2 rounded-md border border-border/70 bg-background/60 px-3 py-2 sm:flex-row sm:items-center sm:justify-between"
                >
                  <code className="break-all font-mono text-[11px] text-foreground">{url}</code>
                  <div className="flex shrink-0 items-center gap-2">
                    <Button
                      size="xs"
                      variant="outline"
                      onClick={() => void copyText(url, "URL")}
                    >
                      <CopyIcon className="size-3.5" />
                      Copy
                    </Button>
                    {window.desktopBridge?.openExternal ? (
                      <Button
                        size="xs"
                        variant="outline"
                        onClick={() => void window.desktopBridge?.openExternal(url)}
                      >
                        <ExternalLinkIcon className="size-3.5" />
                        Open
                      </Button>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          </SettingsRow>
        ) : null}
      </SettingsSection>

      {remoteActive ? (
        <SettingsSection title="Pair a device">
          <SettingsRow
            title="Pairing link"
            description="Generate a one-time link to sign in from a phone browser. Links expire after a few minutes."
            control={
              <Button
                size="xs"
                variant="outline"
                disabled={createPairingLink.isPending}
                onClick={() => createPairingLink.mutate()}
              >
                {createPairingLink.isPending ? "Creating..." : "Create link"}
              </Button>
            }
          >
            {pairingUrl ? (
              <div className="mt-3 space-y-2 rounded-md border border-border/70 bg-background/60 px-3 py-2">
                <code className="block break-all font-mono text-[11px] text-foreground">
                  {pairingUrl}
                </code>
                <div className="flex flex-wrap gap-2">
                  <Button size="xs" variant="outline" onClick={() => void copyText(pairingUrl, "Pairing link")}>
                    <CopyIcon className="size-3.5" />
                    Copy link
                  </Button>
                  {window.desktopBridge?.openExternal ? (
                    <Button
                      size="xs"
                      variant="outline"
                      onClick={() => void window.desktopBridge?.openExternal(pairingUrl)}
                    >
                      <ExternalLinkIcon className="size-3.5" />
                      Open
                    </Button>
                  ) : null}
                </div>
              </div>
            ) : null}
          </SettingsRow>

          <SettingsRow
            title="Connected clients"
            description="Browsers and devices currently paired to this server."
          >
            <div className="space-y-2 pt-1">
              {(clientsQuery.data ?? []).length === 0 ? (
                <p className="text-xs text-muted-foreground">No paired clients yet.</p>
              ) : (
                (clientsQuery.data ?? []).map((client) => (
                  <div
                    key={client.sessionId}
                    className="flex flex-col gap-2 rounded-md border border-border/70 bg-background/60 px-3 py-2 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-xs font-medium text-foreground">
                        {formatClientLabel(client)}
                        {client.current ? " (this device)" : null}
                      </p>
                      <p className="text-[11px] text-muted-foreground">
                        {client.connected ? "Connected" : "Idle"} · {client.role}
                      </p>
                    </div>
                    {!client.current ? (
                      <Button
                        size="xs"
                        variant="outline"
                        disabled={revokeClient.isPending}
                        onClick={() => revokeClient.mutate(client.sessionId)}
                      >
                        Revoke
                      </Button>
                    ) : null}
                  </div>
                ))
              )}
            </div>
          </SettingsRow>
        </SettingsSection>
      ) : null}
    </div>
  );
}
