import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import type { JWK } from 'jose';
import lockfile from 'proper-lockfile';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { DEFAULT_CLIENT_ID, OAUTH_DOMAIN, OAUTH_ISSUER, OAUTH_REDIRECT_URI } from './authConfig.js';
import type { PuraAuthTokens } from './puraTypes.js';

type Fetcher = typeof globalThis.fetch;
type Claims = Record<string, unknown>;
type Pending = { state: string; nonce: string; verifier: string; expires: number };
type SavedSession = { version: 1; clientId: string; tokens: PuraAuthTokens };

function claims(token: string): Claims {
  try {
    return decodeJwt(token);
  } catch {
    throw new Error('Invalid Pura OAuth token. Sign in again.');
  }
}

/** PKCE login, verified Cognito tokens, and a private refreshable session shared by UI and runtime. */
export class PuraOAuthSession {
  private pending: Pending | undefined;
  private refreshing: Promise<PuraAuthTokens> | undefined;
  private keys: JWK[] | undefined;
  private subject: string | undefined;
  readonly sessionPath: string;

  constructor(
    storagePath: string,
    private readonly fetcher: Fetcher = globalThis.fetch,
    private readonly now: () => number = Date.now,
  ) {
    if (!storagePath) {
      throw new Error('Homebridge storage path is unavailable.');
    }
    this.sessionPath = path.join(storagePath, 'pura-oauth', 'session.json');
  }

  start(provider: 'apple' | 'google' | 'login' = 'apple'): { authorizationUrl: string; expiresAt: number } {
    const state = randomBytes(32).toString('base64url');
    const nonce = randomBytes(32).toString('base64url');
    const verifier = randomBytes(32).toString('base64url');
    this.pending = { state, nonce, verifier, expires: this.now() + 10 * 60_000 };
    const url = new URL('/oauth2/authorize', OAUTH_DOMAIN);
    url.search = new URLSearchParams({
      client_id: DEFAULT_CLIENT_ID,
      redirect_uri: OAUTH_REDIRECT_URI,
      response_type: 'code',
      scope: 'openid email profile',
      state, nonce,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
    }).toString();
    if (provider !== 'login') {
      url.searchParams.set('identity_provider', provider === 'apple' ? 'SignInWithApple' : 'Google');
    }
    return { authorizationUrl: url.href, expiresAt: this.pending.expires };
  }

  async complete(callback: string): Promise<{ connected: true; email: string }> {
    const attempt = this.pending;
    if (!attempt || this.now() >= attempt.expires) {
      throw new Error('Login expired. Start a new Pura sign-in.');
    }
    let url: URL;
    try {
      url = new URL(callback);
    } catch {
      throw new Error('Paste the complete pura://callback URL.');
    }
    if (url.protocol !== 'pura:' || url.hostname !== 'callback' || url.pathname || url.port || url.username || url.password || url.hash) {
      throw new Error('Unexpected Pura callback URL.');
    }
    const state = url.searchParams.getAll('state');
    const code = url.searchParams.getAll('code');
    const stateBuffer = Buffer.from(state[0] ?? '');
    if (state.length !== 1 || stateBuffer.length !== Buffer.byteLength(attempt.state)
      || !timingSafeEqual(stateBuffer, Buffer.from(attempt.state))) {
      throw new Error('Pura login state does not match this browser session.');
    }
    this.pending = undefined;
    if (url.searchParams.has('error')) {
      throw new Error('Pura sign-in was declined. Start again when ready.');
    }
    if (code.length !== 1 || !code[0] || code[0].length > 8192) {
      throw new Error('Missing or invalid Pura authorization code.');
    }
    const tokens = await this.exchange({
      grant_type: 'authorization_code', code: code[0], code_verifier: attempt.verifier, redirect_uri: OAUTH_REDIRECT_URI,
    });
    await this.validate(tokens, attempt.nonce);
    await this.withSessionLock(() => this.save(tokens));
    this.subject = String(claims(tokens.idToken).sub);
    return { connected: true, email: String(claims(tokens.idToken).email ?? '') };
  }

  async current(): Promise<PuraAuthTokens> {
    const saved = await this.read();
    if ([saved.idToken, saved.accessToken].some(token => Number(claims(token).exp) * 1000 <= this.now() + 60_000)) {
      return this.refresh();
    }
    await this.validate(saved);
    this.subject = String(claims(saved.idToken).sub);
    return saved;
  }

  refresh(): Promise<PuraAuthTokens> {
    if (this.refreshing) {
      return this.refreshing;
    }
    this.refreshing = (async () => {
      const observed = await this.read();
      return this.withSessionLock(async () => {
        const previous = await this.read();
        if (this.subject && claims(previous.idToken).sub !== this.subject) {
          throw new Error('Pura account changed. Restart the child bridge to load the new account.');
        }
        // A concurrent UI/runtime process may already have rotated this grant.
        if (previous.idToken !== observed.idToken || previous.refreshToken !== observed.refreshToken) {
          await this.validate(previous);
          return previous;
        }
        const tokens = await this.exchange({ grant_type: 'refresh_token', refresh_token: previous.refreshToken }, previous.refreshToken);
        await this.validate(tokens);
        if (claims(tokens.idToken).sub !== claims(previous.idToken).sub) {
          throw new Error('Pura OAuth account changed. Sign in again.');
        }
        await this.save(tokens);
        this.subject = String(claims(tokens.idToken).sub);
        return tokens;
      });
    })().finally(() => {
      this.refreshing = undefined;
    });
    return this.refreshing;
  }

  async status(): Promise<{ connected: boolean; email?: string }> {
    try {
      const tokens = await this.current();
      return { connected: true, email: String(claims(tokens.idToken).email ?? '') };
    } catch {
      return { connected: false };
    }
  }

  private async exchange(fields: Record<string, string>, oldRefreshToken?: string): Promise<PuraAuthTokens> {
    try {
      const response = await this.fetcher(`${OAUTH_DOMAIN}/oauth2/token`, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15_000),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: DEFAULT_CLIENT_ID, ...fields }).toString(),
      });
      if (!response.ok) {
        throw new Error();
      }
      const data = await response.json() as Record<string, unknown>;
      if (typeof data.access_token !== 'string' || typeof data.id_token !== 'string'
        || (typeof data.refresh_token !== 'string' && !oldRefreshToken)) {
        throw new Error();
      }
      return { accessToken: data.access_token, idToken: data.id_token, refreshToken: String(data.refresh_token ?? oldRefreshToken) };
    } catch {
      throw new Error('Pura OAuth token exchange failed. Start a new sign-in; callback codes are single-use.');
    }
  }

  private async validate(tokens: PuraAuthTokens, nonce?: string): Promise<void> {
    const id = await this.verifyToken(tokens.idToken, 'id');
    const access = await this.verifyToken(tokens.accessToken, 'access');
    if (id.aud !== DEFAULT_CLIENT_ID || access.client_id !== DEFAULT_CLIENT_ID || typeof id.sub !== 'string'
      || id.sub !== access.sub || (nonce !== undefined && id.nonce !== nonce)) {
      throw new Error('Pura OAuth token identity does not match the login request.');
    }
    if (nonce === undefined && this.subject && this.subject !== id.sub) {
      throw new Error('Pura account changed. Restart the child bridge to load the new account.');
    }
  }

  private async verifyToken(token: string, use: 'id' | 'access'): Promise<Claims> {
    try {
      const header = decodeProtectedHeader(token);
      if (header.alg !== 'RS256' || typeof header.kid !== 'string') {
        throw new Error();
      }
      if (!this.keys?.some(key => key.kid === header.kid)) {
        const response = await this.fetcher(`${OAUTH_ISSUER}/.well-known/jwks.json`, {
          redirect: 'error', signal: AbortSignal.timeout(15_000),
        });
        if (!response.ok) {
          throw new Error();
        }
        const jwks = await response.json() as { keys?: JWK[] };
        if (!Array.isArray(jwks.keys)) {
          throw new Error();
        }
        this.keys = jwks.keys;
      }
      const { payload: data } = await jwtVerify(token, createLocalJWKSet({ keys: this.keys }), {
        issuer: OAUTH_ISSUER, algorithms: ['RS256'], currentDate: new Date(this.now()),
        requiredClaims: ['exp', 'iat', 'sub', 'token_use'],
        ...(use === 'id' ? { audience: DEFAULT_CLIENT_ID } : {}),
      });
      if (data.iss !== OAUTH_ISSUER || data.token_use !== use || typeof data.exp !== 'number'
        || data.exp * 1000 <= this.now() || typeof data.iat !== 'number' || data.iat * 1000 > this.now() + 60_000) {
        throw new Error();
      }
      return data;
    } catch {
      throw new Error('Pura OAuth token verification failed. Sign in again.');
    }
  }

  private async read(): Promise<PuraAuthTokens> {
    try {
      const record = JSON.parse(await fs.readFile(this.sessionPath, 'utf8')) as SavedSession;
      if (record.version !== 1 || record.clientId !== DEFAULT_CLIENT_ID || !record.tokens
        || ['idToken', 'accessToken', 'refreshToken'].some(k => typeof record.tokens[k as keyof PuraAuthTokens] !== 'string')) {
        throw new Error();
      }
      return record.tokens;
    } catch {
      throw new Error('Connect your Pura account in the plugin settings first.');
    }
  }

  private async withSessionLock<T>(task: () => Promise<T>): Promise<T> {
    const directory = path.dirname(this.sessionPath);
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    await fs.chmod(directory, 0o700);
    let compromised = false;
    const release = await lockfile.lock(this.sessionPath, {
      realpath: false, stale: 120_000, update: 20_000,
      retries: { retries: 30, minTimeout: 50, maxTimeout: 500 },
      onCompromised: () => {
        compromised = true;
      },
    });
    try {
      const result = await task();
      if (compromised) {
        throw new Error('Pura session lock was lost. Retry the login or refresh.');
      }
      return result;
    } finally {
      if (!compromised) {
        await release();
      }
    }
  }

  private async save(tokens: PuraAuthTokens): Promise<void> {
    const temporary = `${this.sessionPath}.${randomBytes(8).toString('hex')}.tmp`;
    try {
      await fs.writeFile(temporary, JSON.stringify({ version: 1, clientId: DEFAULT_CLIENT_ID, tokens } satisfies SavedSession), {
        flag: 'wx', mode: 0o600,
      });
      await fs.rename(temporary, this.sessionPath);
    } finally {
      await fs.rm(temporary, { force: true });
    }
  }
}
