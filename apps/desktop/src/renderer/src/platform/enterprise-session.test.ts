import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  setUser: vi.fn(),
  setToken: vi.fn(),
  identify: vi.fn(),
  seal: vi.fn(async () => {}),
  open: vi.fn(async () => null),
  delete: vi.fn(async () => {}),
  has: vi.fn(async () => false),
  restoreSession: vi.fn(() => null as string | null),
}));

vi.mock("@multica/core/auth", () => ({
  useAuthStore: { getState: () => ({ setUser: mocks.setUser }) },
}));

vi.mock("@multica/core/api", () => ({
  api: { setToken: mocks.setToken },
}));

vi.mock("@multica/core/analytics", () => ({
  identify: mocks.identify,
}));

import {
  clearEnterpriseSession,
  createEnterpriseStorage,
  establishEnterpriseSession,
  isEnterpriseSession,
  restoreEnterpriseSession,
} from "./enterprise-session";

beforeEach(async () => {
  vi.clearAllMocks();
  localStorage.clear();
  window.enterpriseAPI = {
    beginAuth: vi.fn(),
    cancelAuth: vi.fn(),
    onAuthCallback: vi.fn(),
    seal: mocks.seal,
    open: mocks.open,
    delete: mocks.delete,
    has: mocks.has,
    restoreSession: mocks.restoreSession,
  };
  // Module-level session state is shared across tests in this file.
  await clearEnterpriseSession();
});

describe("enterprise storage overlay", () => {
  it("delegates non-auth keys to localStorage", () => {
    const storage = createEnterpriseStorage();
    storage.setItem("draft", "x");
    expect(storage.getItem("draft")).toBe("x");
    expect(localStorage.getItem("draft")).toBe("x");
    storage.removeItem("draft");
    expect(storage.getItem("draft")).toBeNull();
  });

  it("reads the personal token from localStorage when no enterprise session is active", () => {
    localStorage.setItem("multica_token", "personal.jwt");
    const storage = createEnterpriseStorage();
    expect(storage.getItem("multica_token")).toBe("personal.jwt");
  });

  it("personal setItem clears the enterprise shadow", async () => {
    mocks.restoreSession.mockReturnValue("ent.jwt");
    restoreEnterpriseSession();
    const storage = createEnterpriseStorage();
    expect(storage.getItem("multica_token")).toBe("ent.jwt");

    storage.setItem("multica_token", "personal.jwt");
    expect(storage.getItem("multica_token")).toBe("personal.jwt");
    expect(isEnterpriseSession()).toBe(false);
    await clearEnterpriseSession();
  });

  it("removeItem drops the enterprise shadow without touching localStorage", async () => {
    mocks.restoreSession.mockReturnValue("ent.jwt");
    restoreEnterpriseSession();
    const storage = createEnterpriseStorage();

    storage.removeItem("multica_token");

    expect(storage.getItem("multica_token")).toBeNull();
    expect(localStorage.getItem("multica_token")).toBeNull();
    await clearEnterpriseSession();
  });
});

describe("restoreEnterpriseSession", () => {
  it("lifts the sealed token into memory and shadows the personal key", () => {
    localStorage.setItem("multica_token", "personal.jwt");
    mocks.restoreSession.mockReturnValue("ent.jwt");

    expect(restoreEnterpriseSession()).toBe(true);
    expect(isEnterpriseSession()).toBe(true);

    const storage = createEnterpriseStorage();
    expect(storage.getItem("multica_token")).toBe("ent.jwt");
    // The enterprise token never lands in renderer storage.
    expect(localStorage.getItem("multica_token")).toBe("personal.jwt");
  });

  it("returns false when no sealed session exists", () => {
    mocks.restoreSession.mockReturnValue(null);
    expect(restoreEnterpriseSession()).toBe(false);
    expect(isEnterpriseSession()).toBe(false);
  });

  it("returns false when the IPC surface is absent or throws", () => {
    // @ts-expect-error - simulating a non-desktop renderer
    window.enterpriseAPI = undefined;
    expect(restoreEnterpriseSession()).toBe(false);

    mocks.restoreSession.mockImplementation(() => {
      throw new Error("ipc down");
    });
    window.enterpriseAPI = { ...window.enterpriseAPI, restoreSession: mocks.restoreSession };
    expect(restoreEnterpriseSession()).toBe(false);
  });
});

describe("establishEnterpriseSession", () => {
  it("seals the token before publishing the session", async () => {
    const user = { id: "u1", email: "e@x", name: "n" } as never;

    await establishEnterpriseSession("ent.jwt", user);

    expect(mocks.seal).toHaveBeenCalledWith("enterprise-session", "ent.jwt");
    expect(mocks.setToken).toHaveBeenCalledWith("ent.jwt");
    expect(mocks.identify).toHaveBeenCalledWith("u1", {
      email: "e@x",
      name: "n",
    });
    expect(mocks.setUser).toHaveBeenCalledWith(user);
    expect(
      mocks.seal.mock.invocationCallOrder[0],
    ).toBeLessThan(mocks.setToken.mock.invocationCallOrder[0]);
    expect(isEnterpriseSession()).toBe(true);
    await clearEnterpriseSession();
  });

  it("never publishes a session whose seal failed", async () => {
    mocks.seal.mockRejectedValue(new Error("vault unavailable"));

    await expect(
      establishEnterpriseSession("ent.jwt", { id: "u1" } as never),
    ).rejects.toThrow("vault unavailable");

    expect(mocks.setToken).not.toHaveBeenCalled();
    expect(mocks.setUser).not.toHaveBeenCalled();
    expect(isEnterpriseSession()).toBe(false);
  });
});

describe("clearEnterpriseSession", () => {
  it("drops the token and deletes the sealed credential", async () => {
    mocks.restoreSession.mockReturnValue("ent.jwt");
    restoreEnterpriseSession();
    expect(isEnterpriseSession()).toBe(true);

    await clearEnterpriseSession();

    expect(isEnterpriseSession()).toBe(false);
    expect(mocks.delete).toHaveBeenCalledWith("enterprise-session");
    expect(createEnterpriseStorage().getItem("multica_token")).toBeNull();
  });

  it("still drops the in-memory token when vault deletion fails", async () => {
    mocks.restoreSession.mockReturnValue("ent.jwt");
    restoreEnterpriseSession();
    mocks.delete.mockRejectedValue(new Error("vault unavailable"));

    await clearEnterpriseSession();

    expect(isEnterpriseSession()).toBe(false);
  });
});
