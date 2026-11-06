import { Buffer } from 'node:buffer';
import { URL, URLSearchParams } from 'node:url';
const { Response } = globalThis;
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PuraOAuthSession } from '../dist/oauth.js';
import { DEFAULT_CLIENT_ID, OAUTH_ISSUER, OAUTH_REDIRECT_URI } from '../dist/authConfig.js';
import { PuraApi } from '../dist/puraApi.js';
import register from '../dist/index.js';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'test', use: 'sig', alg: 'RS256' };
const log = { debug() {}, info() {}, warn() {}, error() {} };
const jwt = (claims, alg = 'RS256') => {
  const encode = v => Buffer.from(JSON.stringify(v)).toString('base64url');
  const data = `${encode({ alg, kid: 'test' })}.${encode(claims)}`;
  return `${data}.${sign('RSA-SHA256', Buffer.from(data), privateKey).toString('base64url')}`;
};

async function fixture(t, modify = () => {}, transform = value => value) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'pura-oauth-test-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  let now = 1_800_000_000_000;
  let nonce;
  let bad = false;
  let refreshes = 0;
  let exchange;
  const fetcher = async (url, options) => {
    if (url.endsWith('/jwks.json')) {
      return Response.json({ keys: [jwk] });
    }
    exchange = new URLSearchParams(options.body);
    if (bad) {
      return new Response('secret token in an upstream error', { status: 400 });
    }
    if (exchange.get('grant_type') === 'refresh_token') {
      refreshes++;
    }
    const shared = { iss: OAUTH_ISSUER, sub: 'account-1', iat: now / 1000, exp: now / 1000 + 3600 };
    const id = { ...shared, aud: DEFAULT_CLIENT_ID, token_use: 'id', nonce, email: 'test@example.invalid' };
    const access = { ...shared, client_id: DEFAULT_CLIENT_ID, token_use: 'access' };
    modify(id, access);
    return Response.json(transform({ id_token: jwt(id), access_token: jwt(access), refresh_token: `refresh-${refreshes}` }));
  };
  const session = new PuraOAuthSession(directory, fetcher, () => now);
  const begin = () => {
    const url = new URL(session.start().authorizationUrl);
    nonce = url.searchParams.get('nonce');
    return url;
  };
  const finish = url => session.complete(`${OAUTH_REDIRECT_URI}?code=once-only&state=${url.searchParams.get('state')}`);
  return { directory, session, begin, finish, fetcher, now: () => now, advance: ms => {
    now += ms;
  },
  fail: () => {
    bad = true;
  }, exchange: () => exchange, refreshes: () => refreshes };
}

test('Apple PKCE login stores verified tokens privately and restores without a password', async t => {
  const f = await fixture(t);
  const url = f.begin();
  assert.equal(url.origin, 'https://auth.pura.co');
  assert.equal(url.searchParams.get('identity_provider'), 'SignInWithApple');
  assert.equal(url.searchParams.get('redirect_uri'), 'pura://callback');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal((await f.finish(url)).connected, true);
  const verifier = f.exchange().get('code_verifier');
  assert.equal(createHash('sha256').update(verifier).digest('base64url'), url.searchParams.get('code_challenge'));
  const st = await fs.stat(f.session.sessionPath);
  assert.equal(st.mode & 0o777, 0o600);
  assert.equal((await fs.stat(path.dirname(f.session.sessionPath))).mode & 0o777, 0o700);
  const restored = new PuraOAuthSession(f.directory, f.fetcher, f.now);
  assert.equal((await restored.status()).email, 'test@example.invalid');
  const api = new PuraApi(log);
  await api.authenticateOAuth(restored);
  assert.equal(typeof api.getIdToken(), 'string');
  await api.refreshToken();
  assert.equal(f.refreshes(), 1);
  await assert.rejects(f.finish(url), /expired/);
});

test('wrong states, duplicate parameters and foreign callbacks cannot exchange a code', async t => {
  const f = await fixture(t); const url = f.begin(); const state = url.searchParams.get('state');
  for (const callback of [
    'https://evil.invalid/?code=x&state='+state,
    `${OAUTH_REDIRECT_URI}?code=x&state=wrong`,
    `${OAUTH_REDIRECT_URI}?code=x&state=${state}&state=${state}`,
    `${OAUTH_REDIRECT_URI}#code=x&state=${state}`,
  ]) {
    await assert.rejects(f.session.complete(callback));
  }
  assert.equal(f.exchange(), undefined);
  await f.finish(url);
});

test('expired attempts fail and a newer attempt invalidates the earlier one', async t => {
  const f = await fixture(t); const first = f.begin(); const second = f.begin();
  await assert.rejects(f.finish(first), /state/);
  f.advance(600_001);
  await assert.rejects(f.finish(second), /expired/);
});

for (const [name, change] of [
  ['issuer', id => {
    id.iss = 'https://evil.invalid';
  }],
  ['audience', id => {
    id.aud = 'another-client';
  }],
  ['nonce', id => {
    id.nonce = 'wrong-nonce';
  }],
  ['expiry', id => {
    id.exp = 1;
  }],
  ['subject', (_id, access) => {
    access.sub = 'another-account';
  }],
  ['token use', id => {
    id.token_use = 'access';
  }],
]) {
  test(`rejects invalid ${name} without persisting a grant`, async t => {
    const f = await fixture(t, change);
    await assert.rejects(f.finish(f.begin()));
    await assert.rejects(fs.access(f.session.sessionPath));
  });
}

test('refreshes expired sessions, coalesces refreshes, persists rotation and preserves last grant on failure', async t => {
  const f = await fixture(t); await f.finish(f.begin()); f.advance(3_600_000);
  await Promise.all([f.session.current(), f.session.current(), f.session.refresh()]);
  assert.equal(f.refreshes(), 1);
  const before = await fs.readFile(f.session.sessionPath, 'utf8');
  assert.equal(JSON.parse(before).tokens.refreshToken, 'refresh-1');
  f.fail();
  await assert.rejects(f.session.refresh(), error => !error.message.includes('secret token'));
  assert.equal(await fs.readFile(f.session.sessionPath, 'utf8'), before);
});

test('keeps the fork legacy platform alias alongside the current alias', () => {
  const names = [];
  register({ registerPlatform(name) {
    names.push(name);
  } });
  assert.deepEqual(names.sort(), ['PuraFragranceDiffuser', 'PuraSmartDiffuser'].sort());
});

for (const [name, transform] of [
  ['signature', value => ({ ...value, id_token: value.id_token.slice(0, -12) + 'tamperedBits' })],
  ['algorithm', value => ({ ...value, id_token: jwt({ ...JSON.parse(Buffer.from(value.id_token.split('.')[1], 'base64url')) }, 'HS256') })],
  ['missing refresh token', value => ({ ...value, refresh_token: undefined })],
]) {
  test(`rejects ${name} before saving a session`, async t => {
    const f = await fixture(t, () => {}, transform);
    await assert.rejects(f.finish(f.begin()));
    await assert.rejects(fs.access(f.session.sessionPath));
  });
}

test('coordinates refresh-token rotation between UI and runtime session instances', async t => {
  const f = await fixture(t); await f.finish(f.begin());
  const other = new PuraOAuthSession(f.directory, f.fetcher, f.now);
  await other.current();
  f.advance(3_600_000);
  await Promise.all([f.session.current(), other.current()]);
  assert.equal(f.refreshes(), 1);
  assert.equal((await f.session.current()).refreshToken, 'refresh-1');
});

test('account replacement requires restarting the old runtime, not silently reusing its cached devices', async t => {
  let account = 'account-1';
  const f = await fixture(t, (id, access) => {
    id.sub = account; access.sub = account;
  });
  await f.finish(f.begin());
  const runtime = new PuraOAuthSession(f.directory, f.fetcher, f.now);
  await runtime.current();
  account = 'account-2';
  await f.finish(f.begin());
  await assert.rejects(runtime.current(), /account changed/);
  await assert.rejects(runtime.refresh(), /account changed/);
  const restarted = new PuraOAuthSession(f.directory, f.fetcher, f.now);
  assert.equal((await restarted.status()).connected, true);
});

async function websiteFixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'pura-website-test-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  let now = 1_800_000_000_000;
  let calls = 0;
  let subject = 'website-account';
  let bad = false;
  let rotate = false;
  let transform = value => value;
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const token = payload => {
    const encode = v => Buffer.from(JSON.stringify(v)).toString('base64url');
    const data = `${encode({ alg: 'ES256', kid: 'website-test' })}.${encode(payload)}`;
    return `${data}.${sign('sha256', Buffer.from(data), { key: ec.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
  };
  const fetcher = async (url, options) => {
    assert.equal(url, 'https://user.trypura.io/v1/auth/refresh');
    assert.equal(options.redirect, 'error');
    assert.equal(options.method, 'POST');
    const request = JSON.parse(options.body);
    assert.equal(typeof request.prt, 'string');
    calls++;
    if (bad) {
      return new Response('upstream private refresh secret', { status: 401 });
    }
    const shared = { sub: subject, aud: 'pura', iat: now / 1000, exp: now / 1000 + 3600 };
    return Response.json(transform({
      pat: { token: token({ ...shared, iss: 'https://user.trypura.io/v1/auth/issue' }), expiresIn: 3600 },
      pit: { token: token({ ...shared, iss: 'pura', email: 'website@example.invalid' }) },
      ...(rotate ? { prt: `rotated-${calls}` } : {}),
    }));
  };
  return {
    directory, session: new PuraOAuthSession(directory, fetcher, () => now), fetcher, token,
    now: () => now, calls: () => calls, advance: ms => {
      now += ms;
    }, fail: () => {
      bad = true;
    },
    account: next => {
      subject = next;
    }, rotate: () => {
      rotate = true;
    },
    transform: next => {
      transform = next;
    },
  };
}

test('website refresh import restores privately and feeds the existing API session', async t => {
  const f = await websiteFixture(t);
  assert.deepEqual(await f.session.connectWebsite('opaque-refresh'), { connected: true, email: 'website@example.invalid' });
  const record = JSON.parse(await fs.readFile(f.session.sessionPath));
  assert.equal(record.tokens.provider, 'website');
  assert.equal(record.tokens.refreshToken, 'opaque-refresh');
  assert.equal((await fs.stat(f.session.sessionPath)).mode & 0o777, 0o600);
  const restored = new PuraOAuthSession(f.directory, f.fetcher, f.now);
  const api = new PuraApi(log);
  await api.authenticateOAuth(restored);
  assert.equal(f.calls(), 2); // Restore reauthenticates with Pura, rather than trusting imported JWTs.
  f.advance(3_601_000);
  await api.refreshToken();
  assert.equal(f.calls(), 3);
  assert.equal((await restored.status()).connected, true);
});

test('website rotation persists and parallel runtime refreshes coalesce', async t => {
  const f = await websiteFixture(t);
  await f.session.connectWebsite('opaque-refresh');
  f.rotate();
  f.advance(120_000);
  const second = new PuraOAuthSession(f.directory, f.fetcher, f.now);
  await Promise.all([f.session.refresh(), f.session.refresh(), second.refresh()]);
  assert.equal(f.calls(), 2);
  const record = JSON.parse(await fs.readFile(f.session.sessionPath));
  assert.equal(record.tokens.refreshToken, 'rotated-2');
});

test('website refresh failures preserve the last grant and never disclose provider secrets', async t => {
  const f = await websiteFixture(t);
  await f.session.connectWebsite('opaque-refresh');
  const previous = await fs.readFile(f.session.sessionPath, 'utf8');
  f.fail();
  await assert.rejects(f.session.refresh(), error => {
    assert.match(error.message, /renewal failed/);
    assert.doesNotMatch(error.message, /upstream private|opaque-refresh/);
    return true;
  });
  assert.equal(await fs.readFile(f.session.sessionPath, 'utf8'), previous);
});

test('website runtime rejects account switches until restarted', async t => {
  const f = await websiteFixture(t);
  await f.session.connectWebsite('opaque-refresh');
  await f.session.current();
  f.account('replacement');
  const ui = new PuraOAuthSession(f.directory, f.fetcher, f.now);
  await ui.connectWebsite('replacement-refresh');
  await assert.rejects(f.session.refresh(), /account changed/);
  const restarted = new PuraOAuthSession(f.directory, f.fetcher, f.now);
  assert.equal((await restarted.current()).refreshToken, 'replacement-refresh');
});

test('website malformed inputs and malformed endpoint responses cannot replace a grant', async t => {
  const f = await websiteFixture(t);
  for (const input of ['', 'bad\r\ncookie', 'x'.repeat(16385)]) {
    await assert.rejects(f.session.connectWebsite(input), /cookie value/);
  }
  assert.equal(f.calls(), 0);
  await f.session.connectWebsite('opaque-refresh');
  const original = await fs.readFile(f.session.sessionPath, 'utf8');
  for (const response of [{}, { pat: { token: 'not-a-jwt' }, pit: { token: 'not-a-jwt' } }]) {
    f.transform(() => response);
    await assert.rejects(f.session.connectWebsite('another-refresh'), /renewal failed/);
    assert.equal(await fs.readFile(f.session.sessionPath, 'utf8'), original);
  }
});


test('website response claims must match the issuer, audience, expiry and account', async t => {
  const f = await websiteFixture(t);
  await f.session.connectWebsite('opaque-refresh');
  const original = await fs.readFile(f.session.sessionPath, 'utf8');
  for (const change of [{ iss: 'foreign' }, { aud: 'foreign' }, { exp: 0 }, { sub: 'foreign' }, { iat: f.now() / 1000 + 3600 }]) {
    f.transform(response => {
      const payload = JSON.parse(Buffer.from(response.pat.token.split('.')[1], 'base64url'));
      return { ...response, pat: { token: f.token({ ...payload, ...change }) } };
    });
    await assert.rejects(f.session.refresh());
    assert.equal(await fs.readFile(f.session.sessionPath, 'utf8'), original);
  }
});
