// @vitest-environment node
import { describe, expect, it } from "vitest";
import {
  planDaemonTokenSync,
  shouldRestartDaemonAfterUserSwitch,
} from "./daemon-token-policy";

const PERSONAL = {
  tokenFromRenderer: "jwt.personal.session",
  cachedToken: undefined as unknown,
  previousUserId: null as string | null,
  userId: "u1",
  enterprise: false,
};

describe("planDaemonTokenSync", () => {
  it("enterprise sessions never write a token, even a mul_ PAT", () => {
    expect(
      planDaemonTokenSync({
        ...PERSONAL,
        tokenFromRenderer: "mul_passed_directly",
        enterprise: true,
      }),
    ).toEqual({ action: "enterprise_skip" });
    expect(
      planDaemonTokenSync({
        ...PERSONAL,
        cachedToken: "mul_cached",
        previousUserId: "u1",
        userId: "u1",
        enterprise: true,
      }),
    ).toEqual({ action: "enterprise_skip" });
  });

  it("passes a renderer-supplied mul_ PAT straight through", () => {
    expect(
      planDaemonTokenSync({
        ...PERSONAL,
        tokenFromRenderer: "mul_from_renderer",
        previousUserId: "u1",
        userId: "u2",
      }),
    ).toEqual({ action: "write", token: "mul_from_renderer" });
  });

  it("reuses the cached PAT only for the same user", () => {
    expect(
      planDaemonTokenSync({
        ...PERSONAL,
        cachedToken: "mul_cached",
        previousUserId: "u1",
        userId: "u1",
      }),
    ).toEqual({ action: "write", token: "mul_cached" });
  });

  it("mints a fresh PAT on first run or user switch", () => {
    expect(
      planDaemonTokenSync({ ...PERSONAL, previousUserId: null, userId: "u1" }),
    ).toEqual({ action: "mint" });
    expect(
      planDaemonTokenSync({
        ...PERSONAL,
        cachedToken: "mul_cached",
        previousUserId: "u1",
        userId: "u2",
      }),
    ).toEqual({ action: "mint" });
  });

  it("mints when the cached token is not a PAT", () => {
    expect(
      planDaemonTokenSync({
        ...PERSONAL,
        cachedToken: "jwt-not-a-pat",
        previousUserId: "u1",
        userId: "u1",
      }),
    ).toEqual({ action: "mint" });
    expect(
      planDaemonTokenSync({
        ...PERSONAL,
        cachedToken: undefined,
        previousUserId: "u1",
        userId: "u1",
      }),
    ).toEqual({ action: "mint" });
  });

  it("mints when the previous user is unknown, even with a cached PAT", () => {
    expect(
      planDaemonTokenSync({
        ...PERSONAL,
        cachedToken: "mul_cached",
        previousUserId: null,
        userId: "u1",
      }),
    ).toEqual({ action: "mint" });
  });
});

describe("shouldRestartDaemonAfterUserSwitch", () => {
  it("restarts only on a known-user switch", () => {
    expect(shouldRestartDaemonAfterUserSwitch("u1", "u2")).toBe(true);
    expect(shouldRestartDaemonAfterUserSwitch("u1", "u1")).toBe(false);
    expect(shouldRestartDaemonAfterUserSwitch(null, "u1")).toBe(false);
  });
});
