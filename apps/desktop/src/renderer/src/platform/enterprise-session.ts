import { useAuthStore } from "@multica/core/auth";
import { api } from "@multica/core/api";
import { identify } from "@multica/core/analytics";
import type { User, StorageAdapter } from "@multica/core/types";
import { ENTERPRISE_SESSION_PROFILE } from "../../../shared/enterprise";

/**
 * Desktop enterprise session state (BND-161).
 *
 * The enterprise session token lives in two places only: the main-process
 * safeStorage vault (durable, ciphertext) and this module's in-memory
 * variable (what the running renderer presents to the API client). It is
 * never written to renderer localStorage, so a personal (localStorage)
 * session and an enterprise session cannot contaminate each other.
 */

let enterpriseToken: string | null = null;

export function isEnterpriseSession(): boolean {
  return enterpriseToken !== null;
}

/**
 * Storage adapter that overlays `multica_token` with the in-memory enterprise
 * token while an enterprise session is active. The shared auth machinery —
 * API client token source, AuthInitializer's boot probe, sliding session
 * renewal, the WebSocket — reads the credential through this adapter, so the
 * enterprise session reuses the whole existing boot/session path without any
 * token ever touching localStorage.
 *
 * Personal logins clear the overlay: the auth store writes the personal token
 * via `setItem`, which hands the key back to localStorage.
 */
export function createEnterpriseStorage(): StorageAdapter {
  return {
    getItem: (key) => {
      if (key === "multica_token") {
        return enterpriseToken ?? localStorage.getItem(key);
      }
      return localStorage.getItem(key);
    },
    setItem: (key, value) => {
      if (key === "multica_token") {
        // A personal credential is taking over — stop shadowing the key.
        enterpriseToken = null;
      }
      localStorage.setItem(key, value);
    },
    removeItem: (key) => {
      if (key === "multica_token") {
        enterpriseToken = null;
      }
      localStorage.removeItem(key);
    },
    keys: () => Object.keys(localStorage),
  };
}

/**
 * Boot-time restore: lift the sealed enterprise session token from the
 * main-process vault into memory. Synchronous (sendSync IPC) because the
 * shared auth machinery reads the credential through the storage adapter at
 * first render. Returns false (plainly) when there is no vault entry, when
 * the vault cannot be read, or when the enterprise IPC surface is absent
 * (e.g. renderer tests), so boot always falls through to the personal path.
 */
export function restoreEnterpriseSession(): boolean {
  if (enterpriseToken) return true;
  try {
    const surface = window.enterpriseAPI;
    if (!surface || typeof surface.restoreSession !== "function") return false;
    const token = surface.restoreSession();
    if (typeof token !== "string" || token.length === 0) return false;
    enterpriseToken = token;
    return true;
  } catch {
    return false;
  }
}

/**
 * Activate an enterprise session after the exchange. The token is sealed
 * before the session is published: a seal failure must never leave the app
 * running a session whose credential was never persisted.
 */
export async function establishEnterpriseSession(
  token: string,
  user: User,
): Promise<void> {
  await window.enterpriseAPI.seal(ENTERPRISE_SESSION_PROFILE, token);
  enterpriseToken = token;
  api.setToken(token);
  identify(user.id, { email: user.email, name: user.name });
  useAuthStore.getState().setUser(user);
}

/**
 * Drop the enterprise session: clear the in-memory token and best-effort
 * remove the sealed credential. Used by explicit logout, session expiry, and
 * when a personal login takes over.
 */
export async function clearEnterpriseSession(): Promise<void> {
  enterpriseToken = null;
  try {
    await window.enterpriseAPI.delete(ENTERPRISE_SESSION_PROFILE);
  } catch {
    // The in-memory session is already gone; vault cleanup is best-effort.
  }
}
