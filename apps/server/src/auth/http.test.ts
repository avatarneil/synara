// FILE: http.test.ts
// Purpose: Covers auth HTTP helpers shared by the Effect and legacy stacks.
// Layer: Server auth tests

import { describe, expect, it } from "vitest";

import { makeEffectAuthRequest } from "./http";

describe("makeEffectAuthRequest", () => {
  it("falls back to the Cookie header when request.cookies is empty", () => {
    const authRequest = makeEffectAuthRequest({
      headers: { cookie: "t3_session=abc123" },
      cookies: {},
    } as never);

    expect(authRequest.cookies.t3_session).toBe("abc123");
  });

  it("prefers parsed request.cookies over the Cookie header", () => {
    const authRequest = makeEffectAuthRequest({
      headers: { cookie: "t3_session=from-header" },
      cookies: { t3_session: "from-request" },
    } as never);

    expect(authRequest.cookies.t3_session).toBe("from-request");
  });
});
