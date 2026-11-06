import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import type { JWK } from 'jose';
import lockfile from 'proper-lockfile';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { DEFAULT_CLIENT_ID, OAUTH_DOMAIN, OAUTH_ISSUER, OAUTH_REDIRECT_URI, WEBSITE_REFRESH_URL, WEBSITE_LOGIN_URL } from './authConfig.js';
import type { PuraAuthTokens } from './puraTypes.js';

type Fetcher = typeof globalThis.fetch;
type Claims = Record<string, unknown>;
type Pending = { state: string; nonce: string; verifier: string; expires: number };
type PendingEmail = {
  attemptId: string; email: string; sessionId: string; createdAt: number; expiresAt: number; tries: number;
};
type SessionTokens = PuraAuthTokens & { provider?: 'website' };
type SavedSession = { version: 1; clientId: string; tokens: SessionTokens };

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
    return this.acceptConnection(tokens);
  }

  async current(): Promise<PuraAuthTokens> {
    const saved = await this.read();
    // Website tokens are authenticated by the fixed HTTPS refresh endpoint on restore.
    // They use a different issuer/key set from Cognito; never accept imported JWTs.
    if (saved.provider === 'website') {
      return this.refresh();
    }
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
        const tokens = previous.provider === 'website'
          ? await this.exchangeWebsite(previous.refreshToken)
          : await this.exchange({ grant_type: 'refresh_token', refresh_token: previous.refreshToken }, previous.refreshToken);
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

  private get emailPath(): string {
    return path.join(path.dirname(this.sessionPath), 'email-login.json');
  }

  async emailStatus(): Promise<{ attemptId: string; email: string; expiresAt: number } | null> {
    return this.withSessionLock(async () => {
      const pending = await this.readEmail();
      if (!pending?.sessionId || pending.tries >= 5) {
        return null;
      }
      return { attemptId: pending.attemptId, email: pending.email, expiresAt: pending.expiresAt };
    });
  }

  private async readEmail(): Promise<PendingEmail | undefined> {
    let pending: PendingEmail;
    try {
      pending = JSON.parse(await fs.readFile(this.emailPath, 'utf8')) as PendingEmail;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return undefined;
      }
      if (!(error instanceof SyntaxError)) {
        throw new Error('Unable to read Pura sign-in storage. Check Homebridge storage permissions.', { cause: error });
      }
      await fs.rm(this.emailPath, { force: true });
      return undefined;
    }
    if (!pending || typeof pending.attemptId !== 'string' || !pending.attemptId || pending.attemptId.length > 128
      || typeof pending.email !== 'string' || pending.email.length > 254
      || typeof pending.sessionId !== 'string' || pending.sessionId.length > 16384
      || !Number.isInteger(pending.tries) || pending.tries < 0 || pending.tries > 5
      || !Number.isFinite(pending.createdAt) || !Number.isFinite(pending.expiresAt)
      || pending.createdAt > this.now() + 60_000 || pending.expiresAt <= this.now()
      || pending.expiresAt - pending.createdAt !== 10 * 60_000) {
      await fs.rm(this.emailPath, { force: true });
      return undefined;
    }
    return pending;
  }

  async startEmail(emailValue: string): Promise<{ attemptId: string; expiresAt: number }> {
    const email = emailValue.trim();
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw new Error('Enter your existing Pura account email address.');
    }
    return this.withSessionLock(async () => {
      const previous = await this.readEmail();
      if (previous && this.now() - previous.createdAt < 30_000) {
        throw new Error('Wait 30 seconds before requesting another email code.');
      }
      const createdAt = this.now();
      const pending: PendingEmail = {
        attemptId: randomBytes(32).toString('base64url'), email, sessionId: '',
        createdAt, expiresAt: createdAt + 10 * 60_000, tries: 0,
      };
      // Persist the cooldown even when delivery fails; no verification code is stored.
      await this.writePrivateJson(this.emailPath, pending);
      try {
        const data = await this.loginRequest({ method: 'otp', email });
        if (this.now() >= pending.expiresAt || typeof data.sessionId !== 'string'
          || !data.sessionId || data.sessionId.length > 16384) {
          throw new Error();
        }
        pending.sessionId = data.sessionId;
        await this.writePrivateJson(this.emailPath, pending);
        return { attemptId: pending.attemptId, expiresAt: pending.expiresAt };
      } catch {
        throw new Error('Unable to send the Pura email code. Wait briefly and try again.');
      }
    });
  }

  async verifyEmail(attemptId: string, code: string): Promise<{ connected: true; email: string }> {
    if (!/^\d{6}$/.test(code)) {
      throw new Error('Enter the six-digit code from your Pura email.');
    }
    return this.withSessionLock(async () => {
      const pending = await this.readEmail();
      if (!pending?.sessionId || pending.attemptId !== attemptId || pending.tries >= 5) {
        throw new Error('Pura email sign-in expired or was replaced. Request a new code in this window.');
      }
      pending.tries++;
      await this.writePrivateJson(this.emailPath, pending);
      let failure = 'Pura could not verify the code. Request a fresh code in this same settings window and try again.';
      try {
        const data = await this.loginRequest({
          method: 'otpVerify', email: pending.email, sessionId: pending.sessionId, code,
        });
        failure = 'Pura accepted the code but did not return a usable refresh credential. The plugin needs a compatibility update.';
        const credential = data.prt;
        const refreshValue = typeof credential === 'string' ? credential
          : credential && typeof credential === 'object' && 'token' in credential ? credential.token : undefined;
        if (typeof refreshValue !== 'string') {
          throw new Error();
        }
        failure = 'Pura accepted the code but could not renew the login session. Try signing in again.';
        const tokens = await this.exchangeWebsite(refreshValue);
        failure = 'Pura returned a different account or the sign-in expired. Request a fresh code for your existing account email.';
        if (this.now() >= pending.expiresAt
          || String(claims(tokens.idToken).email ?? '').toLowerCase() !== pending.email.toLowerCase()) {
          throw new Error();
        }
        failure = 'Pura verified the account but the private session could not be saved. Check Homebridge storage permissions.';
        return await this.commitConnection(tokens);
      } catch {
        throw new Error(failure);
      }
    });
  }

  private async loginRequest(fields: Record<string, string>): Promise<Record<string, unknown>> {
    const response = await this.fetcher(WEBSITE_LOGIN_URL, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15_000),
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(fields),
    });
    if (!response.ok) {
      throw new Error('Pura email sign-in request failed.');
    }
    return await response.json() as Record<string, unknown>;
  }

  async connectWebsite(refreshValue: string): Promise<{ connected: true; email: string }> {
    const prt = refreshValue.trim();
    if (!prt || prt.length > 16384 || [...prt].some(character => character.charCodeAt(0) <= 32 || character.charCodeAt(0) === 127)) {
      throw new Error('Paste only the __prt cookie value from your signed-in Pura website.');
    }
    const tokens = await this.exchangeWebsite(prt);
    // An explicit connection may replace the account; existing runtime instances stay pinned.
    return this.acceptConnection(tokens);
  }

  private async acceptConnection(tokens: SessionTokens): Promise<{ connected: true; email: string }> {
    return this.withSessionLock(() => this.commitConnection(tokens));
  }

  private async commitConnection(tokens: SessionTokens): Promise<{ connected: true; email: string }> {
    await fs.rm(this.emailPath, { force: true });
    await this.save(tokens);
    this.subject = String(claims(tokens.idToken).sub);
    return { connected: true, email: String(claims(tokens.idToken).email ?? '') };
  }

  private async exchangeWebsite(prt: string): Promise<SessionTokens> {
    try {
      const response = await this.fetcher(WEBSITE_REFRESH_URL, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15_000),
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ prt }),
      });
      if (!response.ok) {
        throw new Error();
      }
      const data = await response.json() as {
        pat?: { token?: unknown }; pit?: { token?: unknown }; prt?: unknown;
      };
      if (typeof data.pat?.token !== 'string' || typeof data.pit?.token !== 'string'
        || (data.prt !== undefined && (typeof data.prt !== 'string' || !data.prt))) {
        throw new Error();
      }
      const tokens: SessionTokens = {
        provider: 'website', accessToken: data.pat.token, idToken: data.pit.token,
        refreshToken: typeof data.prt === 'string' ? data.prt : prt,
      };
      this.validateWebsite(tokens);
      return tokens;
    } catch {
      throw new Error('Pura website session renewal failed. Sign in at pura.com and import a fresh __prt cookie value.');
    }
  }

  private validateWebsite(tokens: SessionTokens): void {
    const id = claims(tokens.idToken);
    const access = claims(tokens.accessToken);
    for (const [token, data, issuer] of [
      [tokens.idToken, id, 'pura'],
      [tokens.accessToken, access, 'https://user.trypura.io/v1/auth/issue'],
    ] as const) {
      if (decodeProtectedHeader(token).alg !== 'ES256' || data.iss !== issuer || data.aud !== 'pura'
        || typeof data.sub !== 'string' || !data.sub || typeof data.exp !== 'number'
        || data.exp * 1000 <= this.now() || typeof data.iat !== 'number'
        || data.iat * 1000 > this.now() + 60_000) {
        throw new Error('Invalid Pura website session response. Sign in again.');
      }
    }
    if (id.sub !== access.sub) {
      throw new Error('Pura website tokens belong to different accounts.');
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

  private async validate(tokens: SessionTokens, nonce?: string): Promise<void> {
    if (tokens.provider === 'website') {
      this.validateWebsite(tokens);
      if (this.subject && this.subject !== claims(tokens.idToken).sub) {
        throw new Error('Pura account changed. Restart the child bridge to load the new account.');
      }
      return;
    }
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

  private async read(): Promise<SessionTokens> {
    try {
      const record = JSON.parse(await fs.readFile(this.sessionPath, 'utf8')) as SavedSession;
      if (record.version !== 1 || record.clientId !== DEFAULT_CLIENT_ID || !record.tokens
        || (record.tokens.provider !== undefined && record.tokens.provider !== 'website')
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

  private async save(tokens: SessionTokens): Promise<void> {
    await this.writePrivateJson(this.sessionPath, { version: 1, clientId: DEFAULT_CLIENT_ID, tokens } satisfies SavedSession);
  }

  private async writePrivateJson(target: string, value: unknown): Promise<void> {
    const temporary = `${target}.${randomBytes(8).toString('hex')}.tmp`;
    try {
      await fs.writeFile(temporary, JSON.stringify(value), { flag: 'wx', mode: 0o600 });
      await fs.rename(temporary, target);
    } finally {
      await fs.rm(temporary, { force: true });
    }
  }
}
