import type { User } from "@multica/core/types";
import type { EnterpriseCallbackPayload } from "../../../shared/enterprise";

/**
 * Desktop enterprise login flow (OPEN-104 / BND-161).
 *
 * 1. Main opens a loopback HTTP listener and returns its port + one-time
 *    state (`enterprise:begin-auth`).
 * 2. The renderer asks the code server to begin the login: POST
 *    /api/enterprise/begin proxies platform INT-101a and returns the
 *    platform `authorize_url` (the renderer never builds the URL itself).
 * 3. The system browser opens that URL with
 *    `redirect_uri=http://127.0.0.1:<port>/callback`.
 * 4. The browser lands back on loopback; main pushes the authorization code
 *    to the renderer (`enterprise:callback`).
 * 5. The renderer exchanges the code for a local session via the code
 *    server's POST /api/enterprise/exchange and hands the token to
 *    `establishEnterpriseSession`, which seals it in the main-process
 *    safeStorage vault.
 *
 * The `multica://` deep link stays reserved for the existing web login; the
 * enterprise flow never registers or consumes a custom protocol.
 */

/** Shape of POST /api/enterprise/exchange — the standard login response. */
export interface EnterpriseExchangeResult {
  token: string;
  user: User;
}

/**
 * Body of POST /api/enterprise/exchange for the loopback code path. The
 * authorization code the browser came back with is one-time; the code server
 * trades it at the platform token endpoint (with the PKCE verifier and the
 * desktop device fingerprint) for the exchange token, then runs the
 * code-exchange step. `device` is optional and passes through when present.
 */
export interface EnterpriseExchangeInput {
  code: string;
  code_verifier: string;
  device?: string;
}

// The exchange response feeds the shared auth store, so validate the fields
// the store reads and default the rest like UserSchema does — a malformed
// response fails the login loudly instead of corrupting downstream state.
function parseExchangeResponse(raw: unknown): EnterpriseExchangeResult | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const body = raw as Record<string, unknown>;
  if (typeof body.token !== "string" || body.token.length === 0) return null;
  const rawUser = body.user;
  if (!rawUser || typeof rawUser !== "object" || Array.isArray(rawUser)) {
    return null;
  }
  const u = rawUser as Record<string, unknown>;
  if (typeof u.id !== "string" || u.id.length === 0) return null;
  const user: User = {
    id: u.id,
    name: typeof u.name === "string" ? u.name : "",
    email: typeof u.email === "string" ? u.email : "",
    avatar_url: typeof u.avatar_url === "string" ? u.avatar_url : null,
    onboarded_at:
      typeof u.onboarded_at === "string" ? u.onboarded_at : null,
    onboarding_questionnaire:
      u.onboarding_questionnaire &&
      typeof u.onboarding_questionnaire === "object" &&
      !Array.isArray(u.onboarding_questionnaire)
        ? (u.onboarding_questionnaire as Record<string, unknown>)
        : {},
    language: typeof u.language === "string" ? u.language : null,
    profile_description:
      typeof u.profile_description === "string" ? u.profile_description : "",
    timezone: typeof u.timezone === "string" ? u.timezone : null,
    created_at: typeof u.created_at === "string" ? u.created_at : "",
    updated_at: typeof u.updated_at === "string" ? u.updated_at : "",
  };
  return { token: body.token, user };
}

function exchangeErrorMessage(raw: unknown, status: number): string {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const message = (raw as Record<string, unknown>).error;
    if (typeof message === "string" && message.length > 0) return message;
  }
  return `Enterprise sign-in failed (HTTP ${status})`;
}

/**
 * Trade the loopback authorization code for a local enterprise session.
 * The code is submitted as `code` together with the attempt's PKCE
 * `code_verifier` — the code server forwards both to the platform token
 * endpoint (S256 re-check against the begin-time challenge, 400
 * AUTH_STATE_MISMATCH on mismatch) and then code-exchanges the resulting
 * exchange token. Throws with the server's message (or an HTTP status
 * fallback) on failure.
 */
export async function exchangeEnterpriseCode(
  apiUrl: string,
  input: EnterpriseExchangeInput,
): Promise<EnterpriseExchangeResult> {
  const res = await fetch(
    `${apiUrl.replace(/\/+$/, "")}/api/enterprise/exchange`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: input.code,
        code_verifier: input.code_verifier,
        ...(input.device ? { device: input.device } : {}),
      }),
    },
  );
  const raw: unknown = await res.json().catch(() => null);
  const parsed = parseExchangeResponse(raw);
  if (!res.ok || !parsed) {
    throw new Error(exchangeErrorMessage(raw, res.status));
  }
  return parsed;
}

/** Shape of POST /api/enterprise/begin — the platform login transaction. */
export interface EnterpriseBeginResult {
  login_txn_id: string;
  authorize_url: string;
}

function parseBeginResponse(raw: unknown): EnterpriseBeginResult | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const body = raw as Record<string, unknown>;
  if (
    typeof body.login_txn_id !== "string" ||
    body.login_txn_id.length === 0 ||
    typeof body.authorize_url !== "string" ||
    body.authorize_url.length === 0
  ) {
    return null;
  }
  return { login_txn_id: body.login_txn_id, authorize_url: body.authorize_url };
}

export interface EnterpriseBeginInput {
  state: string;
  code_challenge: string;
  redirect_uri: string;
}

/**
 * Ask the code server to begin one enterprise login (platform INT-101a
 * proxy). The server attaches the pre-registered client id, calls the
 * platform, and returns the authorize URL to open in the browser.
 */
export async function beginEnterpriseLogin(
  apiUrl: string,
  input: EnterpriseBeginInput,
): Promise<EnterpriseBeginResult> {
  const res = await fetch(`${apiUrl.replace(/\/+$/, "")}/api/enterprise/begin`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  const raw: unknown = await res.json().catch(() => null);
  const parsed = parseBeginResponse(raw);
  if (!res.ok || !parsed) {
    throw new Error(exchangeErrorMessage(raw, res.status));
  }
  return parsed;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * One PKCE S256 pair per login attempt. The verifier leaves the machine only
 * at exchange time, where the code server forwards it to the platform's
 * code-exchange endpoint (S256 re-check); the challenge binds the login
 * transaction the way INT-101a expects.
 */
export async function createPkcePair(): Promise<{
  verifier: string;
  challenge: string;
}> {
  const verifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(48)));
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return { verifier, challenge: base64UrlEncode(new Uint8Array(digest)) };
}

export class EnterpriseLoginError extends Error {
  constructor(
    message: string,
    readonly reason: "unavailable" | "expired" | "exchange_failed",
  ) {
    super(message);
    this.name = "EnterpriseLoginError";
  }
}

export interface EnterpriseLoginDeps {
  beginAuth: () => Promise<
    | { ok: true; port: number; state: string }
    | { ok: false; error: "expired" | "unavailable" }
  >;
  cancelAuth: () => Promise<void>;
  onAuthCallback: (
    callback: (payload: EnterpriseCallbackPayload) => void,
  ) => () => void;
  openExternal: (url: string) => Promise<void>;
  exchange: (
    input: EnterpriseExchangeInput,
  ) => Promise<EnterpriseExchangeResult>;
  begin: (input: EnterpriseBeginInput) => Promise<EnterpriseBeginResult>;
}

/**
 * Run one enterprise login attempt end to end. Resolves with the exchanged
 * session; rejects with EnterpriseLoginError for every terminal failure
 * (listener unavailable, begin rejected, state expired, exchange rejected).
 * Cleans up the loopback listener and the callback subscription on every
 * path.
 */
export async function runEnterpriseLogin(
  deps: EnterpriseLoginDeps,
): Promise<EnterpriseExchangeResult> {
  const begin = await deps.beginAuth();
  if (!begin.ok) {
    throw new EnterpriseLoginError(
      begin.error === "expired"
        ? "The sign-in attempt expired. Try again."
        : "Could not open a local callback listener for enterprise sign-in.",
      begin.error,
    );
  }

  // Holder object: the assignment happens inside a callback, and TS control
  // flow narrows a plain `let` read in `finally` back to its initializer.
  const subscription: { unsubscribe: (() => void) | null } = {
    unsubscribe: null,
  };

  try {
    const pkce = await createPkcePair();
    // The verifier stays local to the attempt until the exchange, where it
    // is forwarded to the platform as code_verifier (S256 re-check).
    let txn: EnterpriseBeginResult;
    try {
      txn = await deps.begin({
        state: begin.state,
        code_challenge: pkce.challenge,
        redirect_uri: `http://127.0.0.1:${begin.port}/callback`,
      });
    } catch (err) {
      // A rejected begin means the integration is unavailable (not
      // configured, platform unreachable) — surface it as such.
      throw new EnterpriseLoginError(
        err instanceof Error ? err.message : "Enterprise sign-in is unavailable.",
        "unavailable",
      );
    }

    const codePromise = new Promise<string>((resolve, reject) => {
      subscription.unsubscribe = deps.onAuthCallback((payload) => {
        if ("code" in payload && payload.code) {
          resolve(payload.code);
          return;
        }
        const expired = !("code" in payload) && payload.error === "expired";
        reject(
          new EnterpriseLoginError(
            expired
              ? "The sign-in attempt expired. Try again."
              : "Enterprise sign-in failed.",
            expired ? "expired" : "exchange_failed",
          ),
        );
      });
    });

    await deps.openExternal(txn.authorize_url);

    const code = await codePromise;
    // The verifier stays attached to the attempt until here: it is submitted
    // with the code so the platform can re-check S256 and bind the exchange
    // token to this login transaction.
    return await deps.exchange({ code, code_verifier: pkce.verifier });
  } finally {
    subscription.unsubscribe?.();
    await deps.cancelAuth().catch(() => {});
  }
}
