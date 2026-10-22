/**
 * Pure decision logic for what the daemon profile's config.json may receive
 * during a token sync. Extracted from daemon-manager so the enterprise gate
 * (BND-161) is unit-testable without touching the filesystem or the network.
 *
 * Enterprise sessions never write a PAT: daemon task claims authenticate
 * through platform task leases instead. Personal sessions keep the existing
 * behavior — pass a `mul_` token straight through, reuse the cached PAT only
 * for the same user, otherwise mint a fresh one.
 */

export type DaemonTokenPlan =
  | { action: "enterprise_skip" }
  | { action: "write"; token: string }
  | { action: "mint" };

export interface PlanDaemonTokenInput {
  /** Credential the renderer presented for this session. */
  tokenFromRenderer: string;
  /** Current `token` value in the profile config, if any. */
  cachedToken: unknown;
  /** User the cached PAT was minted for; null when unknown. */
  previousUserId: string | null;
  /** User the current session belongs to. */
  userId: string;
  /** True when the active session is an enterprise (platform) session. */
  enterprise: boolean;
}

export function planDaemonTokenSync(
  input: PlanDaemonTokenInput,
): DaemonTokenPlan {
  if (input.enterprise) return { action: "enterprise_skip" };

  if (input.tokenFromRenderer.startsWith("mul_")) {
    return { action: "write", token: input.tokenFromRenderer };
  }

  const userChanged =
    Boolean(input.previousUserId) && input.previousUserId !== input.userId;
  const sameUserWithCachedPat =
    !userChanged &&
    input.previousUserId === input.userId &&
    typeof input.cachedToken === "string" &&
    (input.cachedToken as string).startsWith("mul_");
  if (sameUserWithCachedPat) {
    return { action: "write", token: input.cachedToken as string };
  }

  return { action: "mint" };
}

/** Whether this sync should restart a live daemon for a user switch. */
export function shouldRestartDaemonAfterUserSwitch(
  previousUserId: string | null,
  userId: string,
): boolean {
  return Boolean(previousUserId) && previousUserId !== userId;
}
