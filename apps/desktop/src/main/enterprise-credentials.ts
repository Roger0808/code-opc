import { app, safeStorage } from "electron";
import { readFileSync } from "fs";
import { chmod, mkdir, readFile, rm, writeFile } from "fs/promises";
import { dirname, join } from "path";

/**
 * Enterprise credential vault (BND-161).
 *
 * Enterprise session/refresh material is sealed with Electron safeStorage
 * (macOS Keychain-backed) and only the ciphertext ever touches disk, in a
 * single JSON file inside the app's userData directory with 0600
 * permissions. The main process is the only holder; the renderer reaches the
 * vault through the narrow `enterprise:seal/open/delete/has` IPC surface and
 * passes plaintext only in memory during the login flow.
 */

const VAULT_FILE_NAME = "enterprise-vault.bin";
const VAULT_SCHEMA_VERSION = 1;
const VAULT_FILE_MODE = 0o600;
const MAX_PROFILE_LENGTH = 128;

interface VaultFile {
  version: number;
  /** profile name -> base64-encoded safeStorage ciphertext. */
  credentials: Record<string, string>;
}

function vaultFilePath(): string {
  return join(app.getPath("userData"), VAULT_FILE_NAME);
}

function validateProfile(profile: string): string {
  if (
    typeof profile !== "string" ||
    profile.length === 0 ||
    profile.length > MAX_PROFILE_LENGTH ||
    profile.trim() !== profile ||
    profile.includes("/") ||
    profile.includes("\\") ||
    profile === "." ||
    profile === ".."
  ) {
    throw new Error("invalid enterprise credential profile");
  }
  return profile;
}

function encryptionAvailable(): boolean {
  try {
    return safeStorage.isEncryptionAvailable();
  } catch {
    return false;
  }
}

async function readVault(path: string): Promise<VaultFile> {
  try {
    const raw = await readFile(path, "utf-8");
    return parseVault(raw);
  } catch {
    // Missing or unreadable vault reads as empty; a corrupt vault is treated
    // the same way so one bad write cannot brick enterprise login forever.
  }
  return { version: VAULT_SCHEMA_VERSION, credentials: {} };
}

function readVaultSync(path: string): VaultFile {
  try {
    return parseVault(readFileSync(path, "utf-8"));
  } catch {
    return { version: VAULT_SCHEMA_VERSION, credentials: {} };
  }
}

function parseVault(raw: string): VaultFile {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (
      parsed &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      typeof (parsed as VaultFile).version === "number" &&
      (parsed as VaultFile).credentials !== null &&
      typeof (parsed as VaultFile).credentials === "object" &&
      !Array.isArray((parsed as VaultFile).credentials)
    ) {
      return {
        version: (parsed as VaultFile).version,
        credentials: (parsed as VaultFile).credentials,
      };
    }
  } catch {
    // Same contract as readVault: undecodable content reads as empty.
  }
  return { version: VAULT_SCHEMA_VERSION, credentials: {} };
}

async function writeVault(path: string, vault: VaultFile): Promise<void> {
  const keys = Object.keys(vault.credentials);
  if (keys.length === 0) {
    // No live credentials — remove the file instead of leaving ciphertext
    // (and the profiles it names) on disk.
    await rm(path, { force: true });
    return;
  }
  await mkdir(dirname(path), { recursive: true });
  const payload = Buffer.from(JSON.stringify(vault), "utf-8");
  await writeFile(path, payload, { mode: VAULT_FILE_MODE });
  // writeFile mode only applies to newly created files; tighten a pre-existing
  // vault that was already on disk with wider permissions.
  await chmod(path, VAULT_FILE_MODE).catch(() => {});
}

/**
 * Seal `plaintext` for `profile` into the vault. Fails closed when the OS
 * credential backend is unavailable (e.g. headless Linux without a keyring):
 * the caller must surface the error instead of silently continuing without
 * durable enterprise credentials.
 */
export async function sealEnterpriseCredential(
  profile: string,
  plaintext: string,
): Promise<void> {
  const key = validateProfile(profile);
  if (typeof plaintext !== "string" || plaintext.length === 0) {
    throw new Error("enterprise credential must be a non-empty string");
  }
  if (!encryptionAvailable()) {
    throw new Error(
      "enterprise credential storage is unavailable on this system",
    );
  }
  const path = vaultFilePath();
  const vault = await readVault(path);
  vault.credentials[key] = safeStorage
    .encryptString(plaintext)
    .toString("base64");
  await writeVault(path, vault);
}

/**
 * Open the credential sealed for `profile`. Returns null when no credential
 * exists, when the vault cannot be decrypted (unavailable backend, corrupt
 * entry), or after any failure — a restore path must never throw into the
 * boot sequence.
 */
export async function openEnterpriseCredential(
  profile: string,
): Promise<string | null> {
  const key = validateProfile(profile);
  const vault = await readVault(vaultFilePath());
  const sealed = vault.credentials[key];
  if (!sealed || !encryptionAvailable()) return null;
  try {
    return safeStorage.decryptString(Buffer.from(sealed, "base64"));
  } catch {
    return null;
  }
}

/** Remove the credential sealed for `profile`, if any. Never throws. */
export async function deleteEnterpriseCredential(
  profile: string,
): Promise<void> {
  let key: string;
  try {
    key = validateProfile(profile);
  } catch {
    return;
  }
  const path = vaultFilePath();
  const vault = await readVault(path);
  if (!(key in vault.credentials)) return;
  delete vault.credentials[key];
  await writeVault(path, vault);
}

/** Whether a credential is sealed for `profile`. Decryption is not required. */
export async function hasEnterpriseCredential(
  profile: string,
): Promise<boolean> {
  let key: string;
  try {
    key = validateProfile(profile);
  } catch {
    return false;
  }
  const vault = await readVault(vaultFilePath());
  return key in vault.credentials;
}

/**
 * Synchronous variant of `openEnterpriseCredential` for the boot-time restore
 * IPC (`enterprise:restore`): the renderer needs the sealed session token
 * before its very first render, so it cannot wait on async file I/O. Same
 * fail-closed contract — null on any miss or failure.
 */
export function openEnterpriseCredentialSync(
  profile: string,
): string | null {
  let key: string;
  try {
    key = validateProfile(profile);
  } catch {
    return null;
  }
  const vault = readVaultSync(vaultFilePath());
  const sealed = vault.credentials[key];
  if (!sealed || !encryptionAvailable()) return null;
  try {
    return safeStorage.decryptString(Buffer.from(sealed, "base64"));
  } catch {
    return null;
  }
}
