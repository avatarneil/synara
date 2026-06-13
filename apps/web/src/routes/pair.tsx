// FILE: pair.tsx
// Purpose: Bootstrap a remote browser session from a one-time pairing link (#token=…).
// Layer: Routing

import type { AuthBootstrapResult } from "@t3tools/contracts";
import { decodeSecurePairingPayload } from "@t3tools/shared/secureRemote";
import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import { Button } from "~/components/ui/button";
import { requestAuthJson } from "~/lib/authHttp";
import {
  getOrCreateSecureRemoteClientIdentity,
  saveTrustedSecureRemoteServer,
} from "~/lib/secureRemoteState";

function readPairingParamsFromLocation(): {
  readonly token: string | null;
  readonly secure: string | null;
} {
  if (typeof window === "undefined") return { token: null, secure: null };
  const pageUrl = new URL(window.location.href);
  const hashParams = new URLSearchParams(pageUrl.hash.slice(1));
  const token =
    hashParams.get("token")?.trim() || pageUrl.searchParams.get("token")?.trim() || null;
  const secure =
    hashParams.get("secure")?.trim() || pageUrl.searchParams.get("secure")?.trim() || null;
  return { token, secure };
}

function PairRouteView() {
  const [status, setStatus] = useState<"pending" | "success" | "error">("pending");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const bootstrapStartedRef = useRef(false);

  useEffect(() => {
    if (bootstrapStartedRef.current) {
      return;
    }
    bootstrapStartedRef.current = true;

    const { token, secure } = readPairingParamsFromLocation();
    if (!token && !secure) {
      setStatus("error");
      setErrorMessage("This pairing link is missing a token.");
      return;
    }

    const bootstrap = async () => {
      if (!secure) {
        if (!token) {
          throw new Error("This pairing link is missing a token.");
        }
        await requestAuthJson<AuthBootstrapResult>("/api/auth/bootstrap", {
          method: "POST",
          body: { credential: token },
        });
        return;
      }

      const securePayload = decodeSecurePairingPayload(secure);
      const clientIdentity = getOrCreateSecureRemoteClientIdentity();
      await requestAuthJson<AuthBootstrapResult>("/api/auth/bootstrap/secure", {
        method: "POST",
        body: {
          credential: securePayload.credential,
          clientDeviceId: clientIdentity.deviceId,
          clientIdentityPublicKey: clientIdentity.identityPublicKey,
        },
      });
      saveTrustedSecureRemoteServer(securePayload);
    };

    void bootstrap()
      .then(() => {
        setStatus("success");
        window.location.replace("/");
      })
      .catch((error) => {
        setStatus("error");
        setErrorMessage(error instanceof Error ? error.message : "Pairing failed.");
      });
  }, []);

  return (
    <div className="flex min-h-dvh items-center justify-center bg-background px-6 py-12 text-foreground">
      <div className="w-full max-w-md space-y-4 rounded-xl border border-border bg-card p-6 shadow-sm">
        <div className="space-y-1">
          <h1 className="text-lg font-medium tracking-tight">Pair with Synara</h1>
          <p className="text-sm text-muted-foreground">
            {status === "pending"
              ? "Signing this browser in to your Synara server..."
              : status === "success"
                ? "Paired successfully. Redirecting..."
                : "We couldn't complete pairing."}
          </p>
        </div>

        {status === "error" && errorMessage ? (
          <div className="space-y-3">
            <p className="text-sm text-destructive">{errorMessage}</p>
            <Button variant="outline" onClick={() => window.location.assign("/")}>
              Go to Synara
            </Button>
          </div>
        ) : null}
      </div>
    </div>
  );
}

export const Route = createFileRoute("/pair")({
  component: PairRouteView,
});
