// @vitest-environment node
import { chmod, mkdtemp, readFile, stat, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The fake safeStorage is a labeled transform, not real crypto: these tests
// exercise the vault file logic (ciphertext-only on disk, 0600, per-profile
// isolation), and the fake guarantees the plaintext can never appear in the
// file even if the real backend were miswired.
const fake = {
  available: true,
  encryptString: (plaintext: string) => Buffer.from(`enc:${plaintext}`, "utf-8"),
  decryptString: (ciphertext: Buffer) => {
    const value = ciphertext.toString("utf-8");
    if (!value.startsWith("enc:")) throw new Error("invalid ciphertext");
    return value.slice("enc:".length);
  },
};

const paths = { userData: "" };

vi.mock("electron", () => ({
  app: { getPath: () => paths.userData },
  safeStorage: {
    isEncryptionAvailable: () => fake.available,
    encryptString: (plaintext: string) => fake.encryptString(plaintext),
    decryptString: (ciphertext: Buffer) => fake.decryptString(ciphertext),
  },
}));

import {
  deleteEnterpriseCredential,
  hasEnterpriseCredential,
  openEnterpriseCredential,
  openEnterpriseCredentialSync,
  sealEnterpriseCredential,
} from "./enterprise-credentials";

const VAULT_FILE = () => join(paths.userData, "enterprise-vault.bin");
const TOKEN = "ent-session-token-abc";

beforeEach(async () => {
  fake.available = true;
  paths.userData = await mkdtemp(join(tmpdir(), "ent-vault-"));
});

describe("enterprise credential vault", () => {
  it("round-trips a sealed credential", async () => {
    await sealEnterpriseCredential("enterprise-session", TOKEN);
    expect(await openEnterpriseCredential("enterprise-session")).toBe(TOKEN);
    expect(openEnterpriseCredentialSync("enterprise-session")).toBe(TOKEN);
    expect(await hasEnterpriseCredential("enterprise-session")).toBe(true);
  });

  it("stores only ciphertext at 0600", async () => {
    await sealEnterpriseCredential("enterprise-session", TOKEN);

    const raw = await readFile(VAULT_FILE(), "utf-8");
    expect(raw).not.toContain(TOKEN);
    expect(raw).toContain(
      Buffer.from(`enc:${TOKEN}`, "utf-8").toString("base64"),
    );

    const mode = (await stat(VAULT_FILE())).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("tightens permissions on a pre-existing vault file", async () => {
    await writeFile(VAULT_FILE(), JSON.stringify({ version: 1 }), {
      mode: 0o644,
    });

    await sealEnterpriseCredential("enterprise-session", TOKEN);

    const mode = (await stat(VAULT_FILE())).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("keeps profiles isolated in one vault file", async () => {
    await sealEnterpriseCredential("enterprise-session", TOKEN);
    await sealEnterpriseCredential("other-profile", "other-secret");

    expect(await openEnterpriseCredential("enterprise-session")).toBe(TOKEN);
    expect(await openEnterpriseCredential("other-profile")).toBe("other-secret");

    await deleteEnterpriseCredential("enterprise-session");
    expect(await openEnterpriseCredential("enterprise-session")).toBeNull();
    expect(await hasEnterpriseCredential("enterprise-session")).toBe(false);
    // Other profiles survive a single delete.
    expect(await openEnterpriseCredential("other-profile")).toBe("other-secret");
  });

  it("removes the vault file when the last credential is deleted", async () => {
    await sealEnterpriseCredential("enterprise-session", TOKEN);
    await deleteEnterpriseCredential("enterprise-session");

    await expect(stat(VAULT_FILE())).rejects.toMatchObject({ code: "ENOENT" });
    expect(await openEnterpriseCredential("enterprise-session")).toBeNull();
  });

  it("returns null for a missing credential instead of throwing", async () => {
    expect(await openEnterpriseCredential("enterprise-session")).toBeNull();
    expect(openEnterpriseCredentialSync("enterprise-session")).toBeNull();
    expect(await hasEnterpriseCredential("enterprise-session")).toBe(false);
    // Deleting nothing is a no-op.
    await expect(
      deleteEnterpriseCredential("enterprise-session"),
    ).resolves.toBeUndefined();
  });

  it("fails closed when the encryption backend is unavailable", async () => {
    fake.available = false;

    await expect(
      sealEnterpriseCredential("enterprise-session", TOKEN),
    ).rejects.toThrow(/unavailable/);
    expect(await hasEnterpriseCredential("enterprise-session")).toBe(false);
  });

  it("returns null on restore when the encryption backend is unavailable", async () => {
    await sealEnterpriseCredential("enterprise-session", TOKEN);
    fake.available = false;

    expect(await openEnterpriseCredential("enterprise-session")).toBeNull();
    expect(openEnterpriseCredentialSync("enterprise-session")).toBeNull();
  });

  it("returns null on restore when the vault entry is corrupt", async () => {
    await sealEnterpriseCredential("enterprise-session", TOKEN);
    await chmod(VAULT_FILE(), 0o600);
    // Ciphertext that did not come from this backend.
    await writeFile(
      VAULT_FILE(),
      JSON.stringify({ version: 1, credentials: { "enterprise-session": "AAAA" } }),
      { mode: 0o600 },
    );

    expect(await openEnterpriseCredential("enterprise-session")).toBeNull();
    expect(openEnterpriseCredentialSync("enterprise-session")).toBeNull();
  });

  it("rejects invalid profiles", async () => {
    await expect(
      sealEnterpriseCredential("", TOKEN),
    ).rejects.toThrow(/invalid enterprise credential profile/);
    await expect(
      sealEnterpriseCredential("../escape", TOKEN),
    ).rejects.toThrow(/invalid enterprise credential profile/);
    await expect(
      sealEnterpriseCredential("a/b", TOKEN),
    ).rejects.toThrow(/invalid enterprise credential profile/);
    expect(await hasEnterpriseCredential("x".repeat(200))).toBe(false);
    expect(openEnterpriseCredentialSync("..")).toBeNull();
  });

  it("rejects empty plaintext", async () => {
    await expect(
      sealEnterpriseCredential("enterprise-session", ""),
    ).rejects.toThrow(/non-empty/);
  });
});
