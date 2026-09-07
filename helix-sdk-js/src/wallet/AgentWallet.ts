import { pbkdf2Sync, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { access, readFile, writeFile } from 'node:fs/promises';
import {
  CredentialAlreadyInWalletError,
  CredentialNotForThisAgentError,
} from '../errors/index.js';
import { derivePublicKey, generateKeyPair, publicKeyToMultibase, signData } from '../core/keys.js';
import type { ServiceEndpoint } from '../core/did.js';
import type { SignedVC } from '../core/schemas/vc.js';
import type { DelegationGrantVC } from '../core/schemas/delegation-grant.js';
import type { HelixClient } from '../client/HelixClient.js';

/** Same detection the grant schema's `superRefine` uses. */
function isDelegationGrantVC(vc: SignedVC): vc is SignedVC<DelegationGrantVC> {
  return Array.isArray(vc.type) && vc.type.includes('DelegationGrantCredential');
}

export interface WalletData {
  did: string;
  publicKeyHex: string;
  privateKeyHex: string;
  credentials: WalletCredential[];
  createdAt: string;
  updatedAt: string;
}

export interface WalletCredential {
  vcId: string;
  vcJson: string;
  type: string[];
  issuer?: string;
  subjectDid?: string;
  addedAt: string;
  updatedAt: string;
}

export interface StoredWalletData {
  version: number;
  did: string;
  publicKeyHex: string;
  encryptedPrivateKey: string;
  authTag: string;
  iv: string;
  salt: string;
  credentials: WalletCredential[];
  createdAt: string;
  updatedAt: string;
}

/**
 * Where the encrypted wallet payload actually lives — a file on disk
 * (default), or anything a caller wires up instead (their own Postgres
 * table, Redis, S3, ...). `locator` is opaque to AgentWallet: a filesystem
 * path for FileWalletStorage, or any caller-defined key (an agent DID
 * works well) for anything else. AgentWallet only ever hands this the
 * already-encrypted payload — it has no idea whether the private key ever
 * touched a file, a database, or the network on its way to disk.
 */
export interface WalletStorage {
  exists(locator: string): Promise<boolean>;
  save(locator: string, data: StoredWalletData): Promise<void>;
  load(locator: string): Promise<StoredWalletData>;
}

export class FileWalletStorage implements WalletStorage {
  async exists(locator: string): Promise<boolean> {
    try {
      await access(locator);
      return true;
    } catch {
      return false;
    }
  }

  async save(locator: string, data: StoredWalletData): Promise<void> {
    await writeFile(locator, JSON.stringify(data, null, 2), 'utf8');
  }

  async load(locator: string): Promise<StoredWalletData> {
    const raw = await readFile(locator, 'utf8');
    return JSON.parse(raw) as StoredWalletData;
  }
}

/**
 * Structural, not a dependency on `pg` — matches the `.query()` shape that
 * `pg.Pool`/`pg.Client` (and most Postgres clients) already expose, so this
 * works with whatever client the integrator already has without adding one
 * to helix-sdk-js. The integrator owns the connection and the schema; this
 * class only ever runs SELECT/INSERT/UPDATE against a table they created.
 *
 * One-time setup (run this yourself — this class never runs DDL):
 *   CREATE TABLE agent_wallets (
 *     locator    TEXT PRIMARY KEY,
 *     data       JSONB NOT NULL,
 *     updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *
 * TODO: this is a reference implementation, not a hardened multi-tenant
 * design — one flat table, no row-level security, no per-tenant key
 * separation beyond whatever `locator` values the caller chooses. Revisit
 * before using this for anything where isolation between locators matters
 * at the database layer, not just the application layer.
 */
export interface PgQueryable {
  query<T = unknown>(sql: string, values?: unknown[]): Promise<{ rows: T[] }>;
}

export class PostgresWalletStorage implements WalletStorage {
  constructor(
    private readonly db: PgQueryable,
    private readonly tableName = 'agent_wallets',
  ) {}

  async exists(locator: string): Promise<boolean> {
    const { rows } = await this.db.query(`SELECT 1 FROM "${this.tableName}" WHERE "locator" = $1`, [
      locator,
    ]);
    return rows.length > 0;
  }

  async save(locator: string, data: StoredWalletData): Promise<void> {
    await this.db.query(
      `INSERT INTO "${this.tableName}" ("locator", "data", "updated_at") VALUES ($1, $2, now())
       ON CONFLICT ("locator") DO UPDATE SET "data" = $2, "updated_at" = now()`,
      [locator, JSON.stringify(data)],
    );
  }

  async load(locator: string): Promise<StoredWalletData> {
    const { rows } = await this.db.query<{ data: StoredWalletData | string }>(
      `SELECT "data" FROM "${this.tableName}" WHERE "locator" = $1`,
      [locator],
    );
    const row = rows[0];
    if (!row) {
      throw new Error(`No wallet found for locator: ${locator}`);
    }
    return typeof row.data === 'string' ? (JSON.parse(row.data) as StoredWalletData) : row.data;
  }
}

/**
 * A passphrase, or a function that produces one on demand — for callers who
 * don't want a raw passphrase living as a literal string in their own code
 * or config (env var, interactive prompt, a secrets manager / KMS call).
 * Resolved exactly once per public wallet operation, never cached across
 * calls, and never logged or stored anywhere by this module.
 */
export type PassphraseInput = string | (() => string | Promise<string>);

async function resolvePassphrase(input: PassphraseInput): Promise<string> {
  const value = typeof input === 'function' ? await input() : input;
  if (!value) {
    throw new Error('Passphrase resolved to an empty value');
  }
  return value;
}

export interface AgentWalletOptions {
  client?: HelixClient;
  privateKeyHex?: string;
  did?: string;
  walletPath?: string;
  passphrase?: string;
  credentials?: WalletCredential[];
  createdAt?: string;
  updatedAt?: string;
  /** Defaults to FileWalletStorage — pass a PostgresWalletStorage (or your own WalletStorage) to persist elsewhere. */
  storage?: WalletStorage;
}

export class AgentWallet {
  private readonly clientInstance: HelixClient | undefined;
  private privateKeyHex: string | undefined;
  private publicKeyHex: string | undefined;
  private didValue: string | undefined;
  private walletPath: string | undefined;
  private passphrase: string | undefined;
  private readonly storage: WalletStorage;
  private walletCredentials: WalletCredential[];
  private createdAt: string | undefined;
  private updatedAt: string | undefined;

  constructor(options: AgentWalletOptions = {}) {
    this.clientInstance = options.client;
    this.walletPath = options.walletPath;
    this.passphrase = options.passphrase;
    this.storage = options.storage ?? new FileWalletStorage();
    this.walletCredentials = options.credentials ?? [];
    this.createdAt = options.createdAt;
    this.updatedAt = options.updatedAt;
    if (options.privateKeyHex) {
      this.privateKeyHex = options.privateKeyHex;
      this.publicKeyHex = derivePublicKey(options.privateKeyHex);
    } else if (options.client) {
      const keyPair = generateKeyPair();
      this.privateKeyHex = keyPair.privateKey;
      this.publicKeyHex = keyPair.publicKey;
    }
    this.didValue = options.did;
  }

  get credentials(): SignedVC[] {
    return this.walletCredentials.map((credential) => JSON.parse(credential.vcJson) as SignedVC);
  }

  get did(): string {
    return this.getDID();
  }

  /** Exposed so free functions (e.g. `delegate()`) can reach the API without wallet needing to re-implement every client call itself. */
  get client(): HelixClient | undefined {
    return this.clientInstance;
  }

  getPublicKey(): string {
    if (!this.publicKeyHex) throw new Error('Wallet has no in-memory public key');
    return this.publicKeyHex;
  }

  getPrivateKeyHex(): string {
    if (!this.privateKeyHex) throw new Error('Wallet has no in-memory private key');
    return this.privateKeyHex;
  }

  getDID(): string {
    if (!this.didValue)
      throw new Error(
        'Wallet has no DID. Pass a live DID into AgentWallet or load an onboarded wallet file.',
      );
    return this.didValue;
  }

  async createDID(subjectType: 'agent' | 'user'): Promise<{ did: string }> {
    if (!this.clientInstance) throw new Error('Wallet has no HelixClient');
    return this.clientInstance.createDID({ subjectType });
  }

  async addService(endpoint: ServiceEndpoint): Promise<unknown> {
    if (!this.clientInstance) throw new Error('Wallet has no HelixClient');
    return this.clientInstance.addServiceEndpoint(this.getDID(), endpoint);
  }

  async removeService(endpointId: string): Promise<unknown> {
    if (!this.clientInstance) throw new Error('Wallet has no HelixClient');
    return this.clientInstance.removeServiceEndpoint(this.getDID(), endpointId);
  }

  async deactivate(reason = 'user_request'): Promise<void> {
    if (!this.clientInstance) throw new Error('Wallet has no HelixClient');
    await this.clientInstance.deactivateDID(this.getDID(), reason);
  }

  sign(data: string | Uint8Array): string {
    if (!this.privateKeyHex) throw new Error('Wallet has no in-memory private key');
    return signData(data, this.privateKeyHex);
  }

  async save(data: WalletData, passphrase: PassphraseInput, locator: string): Promise<void> {
    const resolved = await resolvePassphrase(passphrase);
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = pbkdf2Sync(resolved, salt, 100_000, 32, 'sha256');
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data.privateKeyHex, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const payload: StoredWalletData = {
      version: 1,
      did: data.did,
      publicKeyHex: data.publicKeyHex,
      encryptedPrivateKey: encrypted.toString('hex'),
      authTag: authTag.toString('hex'),
      iv: iv.toString('hex'),
      salt: salt.toString('hex'),
      credentials: data.credentials,
      createdAt: data.createdAt,
      updatedAt: data.updatedAt,
    };
    await this.storage.save(locator, payload);
  }

  private async saveCurrent(): Promise<void> {
    if (
      !this.didValue ||
      !this.publicKeyHex ||
      !this.privateKeyHex ||
      !this.passphrase ||
      !this.walletPath
    ) {
      throw new Error('Wallet is not loaded from a file');
    }
    const now = new Date().toISOString();
    await this.save(
      {
        did: this.didValue,
        publicKeyHex: this.publicKeyHex,
        privateKeyHex: this.privateKeyHex,
        credentials: this.walletCredentials,
        createdAt: this.createdAt ?? now,
        updatedAt: now,
      },
      this.passphrase,
      this.walletPath,
    );
    this.updatedAt = now;
  }

  async load(passphrase: PassphraseInput, locator: string): Promise<WalletData> {
    const resolved = await resolvePassphrase(passphrase);
    const parsed = await this.storage.load(locator);
    try {
      const key = pbkdf2Sync(resolved, Buffer.from(parsed.salt, 'hex'), 100_000, 32, 'sha256');
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(parsed.iv, 'hex'));
      decipher.setAuthTag(Buffer.from(parsed.authTag, 'hex'));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(parsed.encryptedPrivateKey, 'hex')),
        decipher.final(),
      ]);
      return {
        did: parsed.did,
        publicKeyHex: parsed.publicKeyHex,
        privateKeyHex: decrypted.toString('utf8'),
        credentials: parsed.credentials,
        createdAt: parsed.createdAt,
        updatedAt: parsed.updatedAt,
      };
    } catch {
      throw new Error('Invalid passphrase or corrupted wallet');
    }
  }

  async getPrivateKey(passphrase: PassphraseInput, filePath: string): Promise<string> {
    const data = await this.load(passphrase, filePath);
    return data.privateKeyHex;
  }

  async addCredential(vc: SignedVC): Promise<void>;
  async addCredential(
    vcId: string,
    vcJson: string,
    filePath: string,
    passphrase: PassphraseInput,
  ): Promise<void>;
  async addCredential(
    vcOrId: SignedVC | string,
    vcJson?: string,
    filePath?: string,
    passphrase?: PassphraseInput,
  ): Promise<void> {
    if (typeof vcOrId !== 'string') {
      if (!this.didValue) {
        throw new Error(
          'Wallet has no DID. Pass a live DID into AgentWallet or load an onboarded wallet file.',
        );
      }
      const vc = vcOrId;
      if (vc.credentialSubject.id !== this.didValue) {
        throw new CredentialNotForThisAgentError();
      }
      if (this.walletCredentials.some((item) => item.vcId === vc.id)) {
        throw new CredentialAlreadyInWalletError();
      }
      this.walletCredentials = [...this.walletCredentials, AgentWallet.credentialFromVC(vc.id, vc)];
      await this.saveCurrent();
      await this.recordConsentGrant(vc);
      return;
    }
    if (!vcJson || !filePath || !passphrase) {
      throw new Error('vcJson, filePath, and passphrase are required');
    }
    const vcId = vcOrId;
    // Resolved once here, not left to load()/save() to each resolve it
    // separately — a function passphrase (prompt, secrets-manager call)
    // must fire once per logical operation, not once per file touch.
    const resolvedPassphrase = await resolvePassphrase(passphrase);
    const existing = await this.load(resolvedPassphrase, filePath);
    const credential = AgentWallet.credentialFromVC(vcId, vcJson);
    const credentials = [...existing.credentials.filter((item) => item.vcId !== vcId), credential];
    await this.save(
      { ...existing, credentials, updatedAt: new Date().toISOString() },
      resolvedPassphrase,
      filePath,
    );
  }

  /**
   * Emits `CONSENT_GRANTED` when the credential just stored is an SP-issued
   * delegation grant (spec §2a). Runs after the wallet write has already
   * succeeded and swallows everything: a wallet with no client attached, an API
   * that is down, or a grant with unexpected fields must all leave the stored
   * credential untouched and the caller none the wiser.
   */
  private async recordConsentGrant(vc: SignedVC): Promise<void> {
    if (!this.clientInstance || !isDelegationGrantVC(vc)) return;
    try {
      const subject = vc.credentialSubject;
      await this.clientInstance.recordConsentGrantedAudit({
        vcId: vc.id,
        agentDid: subject.id,
        issuer: vc.issuer,
        userDid: subject.userDid,
        scopes: subject.scopes,
        durability: subject.durability,
        grantedAt: new Date().toISOString(),
        source: 'sdk',
      });
    } catch {
      // Best-effort: the grant is already in the wallet.
    }
  }

  async updateCredential(
    vcId: string,
    vcJson: string,
    filePath: string,
    passphrase: PassphraseInput,
  ): Promise<void> {
    await this.addCredential(vcId, vcJson, filePath, passphrase);
  }

  async removeCredential(vcId: string, filePath: string, passphrase: PassphraseInput): Promise<void> {
    const resolvedPassphrase = await resolvePassphrase(passphrase);
    const existing = await this.load(resolvedPassphrase, filePath);
    await this.save(
      {
        ...existing,
        credentials: existing.credentials.filter((item) => item.vcId !== vcId),
        updatedAt: new Date().toISOString(),
      },
      resolvedPassphrase,
      filePath,
    );
  }

  async listCredentials(passphrase: PassphraseInput, filePath: string): Promise<WalletCredential[]> {
    return (await this.load(passphrase, filePath)).credentials;
  }

  async getCredential(
    vcId: string,
    passphrase: PassphraseInput,
    filePath: string,
  ): Promise<WalletCredential | null> {
    return (
      (await this.load(passphrase, filePath)).credentials.find((item) => item.vcId === vcId) ?? null
    );
  }

  /**
   * Selects the most recent DelegationGrantCredential issued by the given SP
   * for the given user. Grants are per (user, agent, service), so type/recency
   * filtering alone (getLatestCredential) cannot pick the right one.
   */
  selectGrant(issuerDid: string, userDid: string): WalletCredential | undefined {
    return this.walletCredentials
      .filter((item) => {
        if (!item.type.includes('DelegationGrantCredential')) return false;
        if (item.issuer !== issuerDid) return false;
        const parsed = JSON.parse(item.vcJson) as {
          credentialSubject?: { userDid?: unknown };
        };
        return parsed.credentialSubject?.userDid === userDid;
      })
      .sort((a, b) => Date.parse(b.addedAt) - Date.parse(a.addedAt))[0];
  }

  async getLatestCredential(
    options: { vcType?: string } | undefined,
    passphrase: PassphraseInput,
    filePath: string,
  ): Promise<WalletCredential | null> {
    const credentials = (await this.load(passphrase, filePath)).credentials
      .filter((item) => !options?.vcType || item.type.includes(options.vcType))
      .sort((a, b) => Date.parse(b.addedAt) - Date.parse(a.addedAt));
    return credentials[0] ?? null;
  }

  static credentialFromVC(vcId: string, vc: string | Record<string, unknown>): WalletCredential {
    const vcJson = typeof vc === 'string' ? vc : JSON.stringify(vc);
    const parsed = typeof vc === 'string' ? (JSON.parse(vc) as Record<string, unknown>) : vc;
    const subject =
      typeof parsed['credentialSubject'] === 'object' && parsed['credentialSubject'] !== null
        ? (parsed['credentialSubject'] as Record<string, unknown>)
        : {};
    const now = new Date().toISOString();
    const credential: WalletCredential = {
      vcId,
      vcJson,
      type: Array.isArray(parsed['type'])
        ? parsed['type'].filter((item): item is string => typeof item === 'string')
        : [],
      addedAt: now,
      updatedAt: now,
    };
    if (typeof parsed['issuer'] === 'string') credential.issuer = parsed['issuer'];
    if (typeof subject['id'] === 'string') credential.subjectDid = subject['id'];
    return credential;
  }

  /**
   * `client` is optional and only used for best-effort audit emission (e.g.
   * `CONSENT_GRANTED`). Wallets loaded without one behave exactly as before.
   */
  static async create(
    walletPath: string,
    passphrase: PassphraseInput,
    client?: HelixClient,
    storage?: WalletStorage,
  ): Promise<AgentWallet> {
    // Resolved once up front: a function passphrase must fire once per
    // create()/load() call, not once per internal read/write below.
    const resolvedPassphrase = await resolvePassphrase(passphrase);
    const resolvedStorage = storage ?? new FileWalletStorage();
    if (await resolvedStorage.exists(walletPath)) {
      return AgentWallet.load(walletPath, resolvedPassphrase, client, resolvedStorage);
    }

    const keyPair = generateKeyPair();
    const now = new Date().toISOString();
    const data: WalletData = {
      did: `did:key:${publicKeyToMultibase(keyPair.publicKey)}`,
      publicKeyHex: keyPair.publicKey,
      privateKeyHex: keyPair.privateKey,
      credentials: [],
      createdAt: now,
      updatedAt: now,
    };
    await new AgentWallet({ storage: resolvedStorage }).save(data, resolvedPassphrase, walletPath);
    return AgentWallet.fromWalletData(data, walletPath, resolvedPassphrase, client, resolvedStorage);
  }

  static async load(
    walletPath: string,
    passphrase: PassphraseInput,
    client?: HelixClient,
    storage?: WalletStorage,
  ): Promise<AgentWallet> {
    const resolvedPassphrase = await resolvePassphrase(passphrase);
    const resolvedStorage = storage ?? new FileWalletStorage();
    const data = await new AgentWallet({ storage: resolvedStorage }).load(resolvedPassphrase, walletPath);
    return AgentWallet.fromWalletData(data, walletPath, resolvedPassphrase, client, resolvedStorage);
  }

  private static fromWalletData(
    data: WalletData,
    walletPath: string,
    passphrase: string,
    client?: HelixClient,
    storage?: WalletStorage,
  ): AgentWallet {
    return new AgentWallet({
      did: data.did,
      privateKeyHex: data.privateKeyHex,
      walletPath,
      passphrase,
      credentials: data.credentials,
      createdAt: data.createdAt,
      updatedAt: data.updatedAt,
      ...(storage ? { storage } : {}),
      // exactOptionalPropertyTypes: only set the key when a client was given.
      ...(client ? { client } : {}),
    });
  }
}
