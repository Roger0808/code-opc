/**
 * Shared contract for the desktop enterprise login flow (OPC platform
 * integration). Main, preload and renderer all consume these channel names
 * and payload shapes so the IPC surface stays in lockstep.
 */

/** Main -> renderer push carrying the loopback callback result. */
export type EnterpriseCallbackPayload = { code: string } | { error: string };

/**
 * Renderer-readable classification of the loopback failure. `expired` means
 * the one-time state reached the end of its TTL before the browser came back;
 * `unavailable` means the main process could not open a loopback listener.
 */
export type EnterpriseCallbackError = "expired" | "unavailable";

/** Result of `enterprise:begin-auth`: the loopback target for this attempt. */
export type EnterpriseAuthBeginResult =
  | { ok: true; port: number; state: string }
  | { ok: false; error: EnterpriseCallbackError };

/**
 * safeStorage vault profile under which the desktop seals the enterprise
 * session credential. Enterprise credentials are never written to renderer
 * localStorage or the daemon profile config — see BND-161.
 */
export const ENTERPRISE_SESSION_PROFILE = "enterprise-session";
