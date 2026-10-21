import { randomBytes } from "crypto";
import { createServer, type Server, type ServerResponse } from "http";

/**
 * Enterprise login loopback callback server (OPEN-104).
 *
 * The desktop's enterprise sign-in opens the platform authorize page in the
 * system browser with `redirect_uri=http://127.0.0.1:<port>/callback`. This
 * server listens on an ephemeral port bound to loopback only, matches the
 * returned `state` against a one-time in-memory entry (10 minute TTL), and
 * pushes the authorization `code` to the renderer over IPC. Requests with an
 * unknown, reused, or expired state get a plain 404 — the port reveals
 * nothing about login state to whatever else on the machine probes it.
 */

export const ENTERPRISE_CALLBACK_PATH = "/callback";
export const ENTERPRISE_STATE_TTL_MS = 10 * 60 * 1_000;

const CALLBACK_SUCCESS_HTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>Multica</title></head>
<body style="font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;color:#222">
<p>Sign-in received. You can close this tab and return to Multica.</p>
</body></html>`;

export interface EnterpriseAuthServerOptions {
  /** Invoked once with the authorization code after a matching callback. */
  onCallback: (code: string) => void;
  /** Invoked when the state expires before any callback arrives. */
  onExpired?: () => void;
  /** Injected state (tests). Defaults to a random URL-safe value. */
  state?: string;
  /** Listen port; 0 (default) asks the kernel for an ephemeral one. */
  port?: number;
  /** State TTL; defaults to ENTERPRISE_STATE_TTL_MS. */
  ttlMs?: number;
}

export interface EnterpriseAuthServerHandle {
  /** The port the server is listening on (ephemeral ports resolved). */
  port: number;
  /** The one-time state this run expects on /callback. */
  state: string;
  /** Idempotent shutdown; in-flight requests are allowed to finish. */
  close: () => Promise<void>;
}

interface PendingState {
  expiresAt: number;
  timer: ReturnType<typeof setTimeout> | null;
}

export async function startEnterpriseAuthServer(
  options: EnterpriseAuthServerOptions,
): Promise<EnterpriseAuthServerHandle> {
  const state = options.state ?? randomBytes(16).toString("base64url");
  const ttlMs = options.ttlMs ?? ENTERPRISE_STATE_TTL_MS;
  const pending = new Map<string, PendingState>();
  let server: Server | null = null;
  let closed = false;

  const expire = (value: string) => {
    const entry = pending.get(value);
    if (!entry) return;
    pending.delete(value);
    if (entry.timer) clearTimeout(entry.timer);
    options.onExpired?.();
  };

  const register = (value: string) => {
    const entry: PendingState = { expiresAt: Date.now() + ttlMs, timer: null };
    if (ttlMs > 0) {
      entry.timer = setTimeout(() => expire(value), ttlMs);
      // Never keep the process alive solely for a pending login.
      entry.timer.unref?.();
    }
    pending.set(value, entry);
  };

  const notFound = (res: ServerResponse) => {
    res.statusCode = 404;
    res.end("not found");
  };

  server = createServer((req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (req.method !== "GET" || url.pathname !== ENTERPRISE_CALLBACK_PATH) {
        notFound(res);
        return;
      }
      const code = url.searchParams.get("code");
      const returnedState = url.searchParams.get("state");
      const entry = returnedState ? pending.get(returnedState) : undefined;
      if (!code || !entry || entry.expiresAt <= Date.now()) {
        // Unknown, reused, or expired state: indistinguishable from any other
        // miss so probes cannot fingerprint in-flight login attempts.
        notFound(res);
        return;
      }
      // One-time use: consume before responding or invoking anything else,
      // so a replayed request lands on the 404 path above.
      pending.delete(returnedState as string);
      if (entry.timer) clearTimeout(entry.timer);
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.end(CALLBACK_SUCCESS_HTML);
      options.onCallback(code);
      void closeServer();
    } catch {
      if (!res.headersSent) notFound(res);
      else res.destroy();
    }
  });

  const closeServer = (): Promise<void> => {
    if (closed) return Promise.resolve();
    closed = true;
    for (const entry of pending.values()) {
      if (entry.timer) clearTimeout(entry.timer);
    }
    pending.clear();
    const current = server;
    server = null;
    if (!current) return Promise.resolve();
    return new Promise((resolve) => current.close(() => resolve()));
  };

  register(state);

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => reject(err);
    server?.once("error", onError);
    server?.listen(options.port ?? 0, "127.0.0.1", () => {
      server?.removeListener("error", onError);
      resolve();
    });
  });

  const address = server?.address();
  const boundPort =
    address && typeof address === "object" ? address.port : (options.port ?? 0);

  return { port: boundPort, state, close: closeServer };
}
