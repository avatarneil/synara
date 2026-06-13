// FILE: RemoteAuthGate.tsx
// Purpose: Browser pairing gate shown before any WebSocket-backed app hydration starts.
// Layer: Web auth UI

import type { AuthBootstrapResult } from "@t3tools/contracts";
import type { FormEvent } from "react";
import { useState } from "react";

import { APP_DISPLAY_NAME } from "../branding";
import { requestAuthJson } from "../lib/authHttp";
import { Button } from "./ui/button";

export function RemoteAuthGate({ onAuthenticated }: { onAuthenticated: () => void }) {
  const [credential, setCredential] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = credential.trim();
    if (!trimmed || isSubmitting) return;

    setIsSubmitting(true);
    setErrorMessage(null);
    void requestAuthJson<AuthBootstrapResult>("/api/auth/bootstrap", {
      method: "POST",
      body: { credential: trimmed },
    })
      .then(() => {
        onAuthenticated();
      })
      .catch((error) => {
        setErrorMessage(error instanceof Error ? error.message : "Pairing failed.");
      })
      .finally(() => {
        setIsSubmitting(false);
      });
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-6 py-12 text-foreground">
      <form
        className="w-full max-w-md space-y-5 rounded-xl border border-border bg-card p-6 shadow-sm"
        onSubmit={submit}
      >
        <div className="space-y-1">
          <p className="text-xs font-medium tracking-[0.18em] text-muted-foreground uppercase">
            {APP_DISPLAY_NAME}
          </p>
          <h1 className="text-xl font-semibold tracking-tight">Pair this browser</h1>
          <p className="text-sm leading-6 text-muted-foreground">
            Enter a pairing token from the desktop app to connect to this server.
          </p>
        </div>

        <label className="block space-y-2">
          <span className="text-sm font-medium text-foreground">Pairing token</span>
          <input
            autoFocus
            className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm outline-none transition-colors placeholder:text-muted-foreground focus:border-ring"
            value={credential}
            onChange={(event) => setCredential(event.target.value)}
            placeholder="ABCD2345WXYZ"
            autoCapitalize="characters"
            autoCorrect="off"
            spellCheck={false}
          />
        </label>

        {errorMessage ? <p className="text-sm text-destructive">{errorMessage}</p> : null}

        <Button type="submit" className="w-full" disabled={isSubmitting || !credential.trim()}>
          {isSubmitting ? "Pairing..." : "Pair"}
        </Button>
      </form>
    </div>
  );
}
