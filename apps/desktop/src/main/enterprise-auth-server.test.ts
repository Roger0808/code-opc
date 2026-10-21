// @vitest-environment node
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  startEnterpriseAuthServer,
  type EnterpriseAuthServerHandle,
} from "./enterprise-auth-server";

const handles: EnterpriseAuthServerHandle[] = [];

async function start(
  ...args: Parameters<typeof startEnterpriseAuthServer>
): Promise<EnterpriseAuthServerHandle> {
  const handle = await startEnterpriseAuthServer(...args);
  handles.push(handle);
  return handle;
}

async function get(
  port: number,
  path: string,
): Promise<{ status: number; body: string }> {
  const res = await fetch(`http://127.0.0.1:${port}${path}`);
  return { status: res.status, body: await res.text() };
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

afterEach(async () => {
  await Promise.all(handles.splice(0).map((h) => h.close()));
  vi.restoreAllMocks();
});

describe("enterprise auth loopback server", () => {
  it("listens on an ephemeral loopback port with the given state", async () => {
    const handle = await start({
      state: "state-1",
      onCallback: () => {},
    });

    expect(handle.port).toBeGreaterThan(0);
    expect(handle.state).toBe("state-1");
    const res = await fetch(`http://127.0.0.1:${handle.port}/callback`);
    // Alive but nothing matches: a miss is indistinguishable from any route.
    expect(res.status).toBe(404);
  });

  it("generates a URL-safe state when none is injected", async () => {
    const a = await start({ onCallback: () => {} });
    const b = await start({ onCallback: () => {} });

    expect(a.state).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(a.state).not.toBe(b.state);
  });

  it("accepts a matching state once and delivers the code", async () => {
    const onCallback = vi.fn();
    const handle = await start({ state: "s", onCallback });

    const res = await get(handle.port, "/callback?code=code-1&state=s");

    expect(res.status).toBe(200);
    expect(res.body).toContain("Sign-in received");
    expect(onCallback).toHaveBeenCalledWith("code-1");
    // The listener shuts down after a successful callback.
    await expect(
      fetch(`http://127.0.0.1:${handle.port}/callback?code=x&state=s`),
    ).rejects.toThrow();
  });

  it("rejects a wrong state with 404 and no callback", async () => {
    const onCallback = vi.fn();
    const handle = await start({ state: "expected", onCallback });

    const res = await get(handle.port, "/callback?code=code-1&state=wrong");

    expect(res.status).toBe(404);
    expect(onCallback).not.toHaveBeenCalled();
  });

  it("rejects a replayed state after the first success", async () => {
    const onCallback = vi.fn();
    const handle = await start({ state: "s", onCallback });

    await get(handle.port, "/callback?code=first&state=s");
    expect(onCallback).toHaveBeenCalledTimes(1);

    // The server is already closed; even if a listener were somehow still
    // around, the one-time state must be gone.
    await expect(
      fetch(`http://127.0.0.1:${handle.port}/callback?code=replay&state=s`),
    ).rejects.toThrow();
  });

  it("rejects requests without a code, other paths, and non-GET methods", async () => {
    const onCallback = vi.fn();
    const handle = await start({ state: "s", onCallback });

    expect((await get(handle.port, "/callback?state=s")).status).toBe(404);
    expect((await get(handle.port, "/other?code=c&state=s")).status).toBe(404);
    const post = await fetch(`http://127.0.0.1:${handle.port}/callback`, {
      method: "POST",
    });
    expect(post.status).toBe(404);
    expect(onCallback).not.toHaveBeenCalled();
  });

  it("expires the state after the TTL and reports the expiry", async () => {
    const onCallback = vi.fn();
    const onExpired = vi.fn();
    const handle = await start({ state: "s", onCallback, onExpired, ttlMs: 40 });

    await sleep(80);

    expect(onExpired).toHaveBeenCalledOnce();
    expect(onCallback).not.toHaveBeenCalled();
    // Post-expiry the same state is a plain miss — the server stays up so a
    // late browser landing still gets a deterministic answer.
    const res = await get(handle.port, "/callback?code=code-1&state=s");
    expect(res.status).toBe(404);
    expect(onCallback).not.toHaveBeenCalled();
  });

  it("close() is idempotent and stops the listener", async () => {
    const handle = await start({ state: "s", onCallback: () => {} });

    await handle.close();
    await handle.close();

    await expect(
      fetch(`http://127.0.0.1:${handle.port}/callback`),
    ).rejects.toThrow();
  });
});
