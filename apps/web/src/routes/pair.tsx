// FILE: pair.tsx
// Purpose: Bootstrap a remote browser session from a one-time pairing link (#token=…).
// Layer: Routing

import type { AuthBootstrapResult } from "@t3tools/contracts";
import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import { Button } from "~/components/ui/button";
import { requestAuthJson } from "~/lib/authHttp";

function readPairingTokenFromLocation(): string | null {
  if (typeof window === "undefined") return null;
  const pageUrl = new URL(window.location.href);
  const fromHash = new URLSearchParams(pageUrl.hash.slice(1)).get("token")?.trim();
  if (fromHash) return fromHash;
  return pageUrl.searchParams.get("token")?.trim() ?? null;
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

    const token = readPairingTokenFromLocation();
    if (!token) {
      setStatus("error");
      setErrorMessage("This pairing link is missing a token.");
      return;
    }

    void requestAuthJson<AuthBootstrapResult>("/api/auth/bootstrap", {
      method: "POST",
      body: { credential: token },
    })
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
