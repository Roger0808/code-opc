// @vitest-environment node
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  beginEnterpriseLogin,
  createPkcePair,
  EnterpriseLoginError,
  exchangeEnterpriseCode,
  runEnterpriseLogin,
  type EnterpriseLoginDeps,
} from "./enterprise-login";

describe("beginEnterpriseLogin", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function stubFetch(impl: (input: string, init?: RequestInit) => unknown) {
    vi.stubGlobal("fetch", vi.fn(impl));
  }

  it("posts the flow parameters to the code server begin endpoint", async () => {
    stubFetch((input: string, init?: RequestInit) => {
      expect(input).toBe("https://api.example.com/api/enterprise/begin");
      expect(init?.method).toBe("POST");
      expect(JSON.parse(String(init?.body))).toEqual({
        state: "state-1",
        code_challenge: "challenge-1",
        redirect_uri: "http://127.0.0.1:49152/callback",
      });
      return Promise.resolve(
        new Response(
          JSON.stringify({
            login_txn_id: "txn-1",
            authorize_url: "https://platform.example.com/wecom/scan?txn=txn-1",
          }),
          { status: 200 },
        ),
      );
    });

    const out = await beginEnterpriseLogin("https://api.example.com/", {
      state: "state-1",
      code_challenge: "challenge-1",
      redirect_uri: "http://127.0.0.1:49152/callback",
    });

    expect(out.login_txn_id).toBe("txn-1");
    expect(out.authorize_url).toBe(
      "https://platform.example.com/wecom/scan?txn=txn-1",
    );
  });

  it("surfaces the server error message on failure", async () => {
    stubFetch(() =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            error: "redirect_uri must be a loopback URL",
            code: "enterprise_redirect_uri_not_allowed",
          }),
          { status: 400 },
        ),
      ),
    );

    await expect(
      beginEnterpriseLogin("https://api.example.com", {
        state: "s",
        code_challenge: "c",
        redirect_uri: "http://example.com/callback",
      }),
    ).rejects.toThrow("redirect_uri must be a loopback URL");
  });

  it("rejects a malformed success body", async () => {
    stubFetch(() =>
      Promise.resolve(
        new Response(JSON.stringify({ login_txn_id: "txn-1" }), {
          status: 200,
        }),
      ),
    );

    await expect(
      beginEnterpriseLogin("https://api.example.com", {
        state: "s",
        code_challenge: "c",
        redirect_uri: "http://127.0.0.1:1/callback",
      }),
    ).rejects.toThrow(/HTTP 200/);
  });
});

describe("createPkcePair", () => {
  it("produces an S256 challenge over a high-entropy verifier", async () => {
    const { verifier, challenge } = await createPkcePair();
    expect(verifier.length).toBeGreaterThanOrEqual(60);
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const { createHash } = await import("node:crypto");
    const expected = createHash("sha256")
      .update(verifier, "ascii")
      .digest()
      .toString("base64url");
    expect(challenge).toBe(expected);
  });
});

describe("exchangeEnterpriseCode", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const okResponse = {
    token: "ent.jwt",
    user: { id: "u1", name: "Yang Jing", email: "enterprise-u1@platform.local" },
  };

  function stubFetch(impl: (input: string, init?: RequestInit) => unknown) {
    vi.stubGlobal("fetch", vi.fn(impl));
  }

  it("posts the code as exchange_token with the PKCE verifier", async () => {
    stubFetch((_input: string, init?: RequestInit) => {
      expect(init?.method).toBe("POST");
      expect(JSON.parse(String(init?.body))).toEqual({
        exchange_token: "code-1",
        code_verifier: "verifier-1",
      });
      return Promise.resolve(
        new Response(JSON.stringify(okResponse), { status: 200 }),
      );
    });

    const result = await exchangeEnterpriseCode(
      "https://api.example.com/",
      "code-1",
      "verifier-1",
    );

    expect(result.token).toBe("ent.jwt");
    expect(result.user.id).toBe("u1");
    expect(result.user.name).toBe("Yang Jing");
  });

  it("defaults user fields the shared store reads", async () => {
    stubFetch(() =>
      Promise.resolve(
        new Response(JSON.stringify({ token: "t", user: { id: "u1" } }), {
          status: 200,
        }),
      ),
    );

    const { user } = await exchangeEnterpriseCode(
      "https://api.example.com",
      "c",
      "v",
    );

    expect(user.email).toBe("");
    expect(user.profile_description).toBe("");
    expect(user.onboarding_questionnaire).toEqual({});
    expect(user.avatar_url).toBeNull();
  });

  it("surfaces the server error message on failure", async () => {
    stubFetch(() =>
      Promise.resolve(
        new Response(JSON.stringify({ error: "replay detected", code: "REPLAY" }), {
          status: 400,
        }),
      ),
    );

    await expect(
      exchangeEnterpriseCode("https://api.example.com", "c", "v"),
    ).rejects.toThrow("replay detected");
  });

  it("falls back to the HTTP status when the body has no message", async () => {
    stubFetch(() =>
      Promise.resolve(new Response("not json", { status: 502 })),
    );

    await expect(
      exchangeEnterpriseCode("https://api.example.com", "c", "v"),
    ).rejects.toThrow(/HTTP 502/);
  });

  it("rejects a malformed success body", async () => {
    stubFetch(() =>
      Promise.resolve(
        new Response(JSON.stringify({ token: 42, user: null }), {
          status: 200,
        }),
      ),
    );

    await expect(
      exchangeEnterpriseCode("https://api.example.com", "c", "v"),
    ).rejects.toThrow(/HTTP 200/);
  });
});

describe("runEnterpriseLogin", () => {
  function makeDeps(overrides: Partial<EnterpriseLoginDeps> = {}) {
    let callback: ((payload: { code: string } | { error: string }) => void) | null =
      null;
    const opened: string[] = [];
    const exchanged: { code: string; codeVerifier: string }[] = [];
    const beginCalls: {
      state: string;
      code_challenge: string;
      redirect_uri: string;
    }[] = [];
    const deps: EnterpriseLoginDeps = {
      beginAuth: vi.fn(async () => ({
        ok: true as const,
        port: 49152,
        state: "state-9",
      })),
      cancelAuth: vi.fn(async () => {}),
      onAuthCallback: (cb) => {
        callback = cb;
        return () => {
          callback = null;
        };
      },
      openExternal: vi.fn(async (url: string) => {
        opened.push(url);
        // The browser completes sign-in as soon as the authorize URL opens.
        callback?.({ code: "code-9" });
      }),
      exchange: vi.fn(async (code: string, codeVerifier: string) => {
        exchanged.push({ code, codeVerifier });
        return { token: "ent.jwt", user: { id: "u1" } as never };
      }),
      begin: vi.fn(async (input) => {
        beginCalls.push(input);
        // The authorize URL comes from the code server's begin response —
        // the renderer never constructs a platform URL itself.
        return {
          login_txn_id: "txn-9",
          authorize_url: "https://platform.example.com/wecom/scan?txn=txn-9",
        };
      }),
      ...overrides,
    };
    return { deps, opened, exchanged, beginCalls, emit: (p: { code: string } | { error: string }) => callback?.(p) };
  }

  it("runs the full loopback flow through the begin proxy and cleans up the listener", async () => {
    const { deps, opened, exchanged, beginCalls } = makeDeps();

    const result = await runEnterpriseLogin(deps);

    expect(result.token).toBe("ent.jwt");
    expect(deps.beginAuth).toHaveBeenCalledOnce();
    expect(beginCalls).toHaveLength(1);
    expect(beginCalls[0].state).toBe("state-9");
    expect(beginCalls[0].code_challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(beginCalls[0].redirect_uri).toBe(
      "http://127.0.0.1:49152/callback",
    );
    // The browser opens exactly the URL the begin endpoint returned.
    expect(opened).toEqual([
      "https://platform.example.com/wecom/scan?txn=txn-9",
    ]);
    // The exchange carries the attempt's PKCE verifier through to the server.
    expect(exchanged).toHaveLength(1);
    expect(exchanged[0].code).toBe("code-9");
    expect(exchanged[0].codeVerifier).toMatch(/^[A-Za-z0-9_-]{60,}$/);
    expect(deps.cancelAuth).toHaveBeenCalledOnce();
  });

  it("fails fast when the loopback listener cannot start", async () => {
    const { deps } = makeDeps({
      beginAuth: (async () => ({
        ok: false as const,
        error: "unavailable" as const,
      })) as EnterpriseLoginDeps["beginAuth"],
    });

    const err = await runEnterpriseLogin(deps).catch((e) => e);
    expect(err).toBeInstanceOf(EnterpriseLoginError);
    expect(err.reason).toBe("unavailable");
    expect(deps.begin).not.toHaveBeenCalled();
    expect(deps.exchange).not.toHaveBeenCalled();
  });

  it("maps a rejected begin to the unavailable reason", async () => {
    const { deps } = makeDeps({
      begin: (async () => {
        throw new Error("enterprise integration is not configured");
      }) as EnterpriseLoginDeps["begin"],
    });

    const err = await runEnterpriseLogin(deps).catch((e) => e);
    expect(err).toBeInstanceOf(EnterpriseLoginError);
    expect(err.reason).toBe("unavailable");
    expect(err.message).toContain("not configured");
    expect(deps.openExternal).not.toHaveBeenCalled();
    expect(deps.cancelAuth).toHaveBeenCalledOnce();
  });

  it("maps an expired callback push to the expired reason", async () => {
    const { deps, emit } = makeDeps({
      openExternal: (async () => {
        emit({ error: "expired" });
      }) as EnterpriseLoginDeps["openExternal"],
    });

    const err = await runEnterpriseLogin(deps).catch((e) => e);
    expect(err).toBeInstanceOf(EnterpriseLoginError);
    expect(err.reason).toBe("expired");
    expect(deps.cancelAuth).toHaveBeenCalledOnce();
  });

  it("unsubscribes the callback and cancels the listener when the exchange fails", async () => {
    const { deps } = makeDeps({
      exchange: (async () => {
        throw new Error("exchange rejected");
      }) as EnterpriseLoginDeps["exchange"],
    });

    await expect(runEnterpriseLogin(deps)).rejects.toThrow("exchange rejected");
    expect(deps.cancelAuth).toHaveBeenCalledOnce();
  });
});
