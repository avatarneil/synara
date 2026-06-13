import Path from "node:path";

import { describe, expect, it } from "vitest";

import { resolveDesktopBackendStateDir } from "./remoteAccessSettings";

describe("remoteAccessSettings", () => {
  it("uses the backend dev state dir when the desktop shell proxies a dev web URL", () => {
    expect(resolveDesktopBackendStateDir("/tmp/synara", "http://localhost:5733")).toBe(
      Path.join("/tmp/synara", "dev"),
    );
  });

  it("uses the normal userdata state dir for packaged desktop builds", () => {
    expect(resolveDesktopBackendStateDir("/tmp/synara", undefined)).toBe(
      Path.join("/tmp/synara", "userdata"),
    );
  });

  it("treats a blank dev URL env var as packaged state", () => {
    expect(resolveDesktopBackendStateDir("/tmp/synara", "  ")).toBe(
      Path.join("/tmp/synara", "userdata"),
    );
  });
});
