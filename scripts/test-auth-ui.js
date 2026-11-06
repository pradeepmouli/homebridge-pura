import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';
import { URL } from 'node:url';
import ts from 'typescript';

const html = await readFile(new URL('../homebridge-ui/public/index.html', import.meta.url), 'utf8');
const script = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(x => x[1]).join('\n');
const source = ts.createSourceFile('settings.js', script, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
let verifyHandler;
function findHandler(node) {
  if (ts.isCallExpression(node) && node.expression.getText(source) === 'verifyCode.addEventListener') {
    verifyHandler = node.arguments[1].getText(source);
  }
  ts.forEachChild(node, findHandler);
}
findHandler(source);
assert.ok(verifyHandler, 'The verification button must have a click handler');

function fixture() {
  const input = { value: '123456' };
  const attrs = new Map();
  const verify = { disabled: false, setAttribute: (k, v) => attrs.set(k, v), removeAttribute: k => attrs.delete(k) };
  const send = { disabled: false };
  let resolve;
  let reject;
  let status;
  let updates = 0;
  const request = new Promise((ok, fail) => {
    resolve = ok; reject = fail;
  });
  const context = {
    document: { getElementById: id => {
      assert.equal(id, 'emailCode'); return input;
    } },
    verifyCode: verify, sendCode: send, emailAttemptId: 'opaque-attempt',
    emailInput: { value: 'account@example.invalid' }, els: { username: { value: '' } }, oauthConnected: false,
    showAuthStatus: (message, failed = false) => {
      status = { message, failed };
    },
    updateSaveState: () => {
      updates++;
    }, syncConfig: async () => {},
    homebridge: { request: (route, payload) => {
      assert.equal(route, '/oauth/email/verify');
      assert.equal(payload.code, '123456');
      assert.equal(payload.attemptId, 'opaque-attempt');
      return request;
    } },
  };
  const run = vm.runInNewContext(`(${verifyHandler})`, context);
  return { input, verify, send, attrs, context, run, resolve: v => resolve(v), reject: e => reject(e), status: () => status, updates: () => updates };
}

test('verification shows progress immediately and preserves the entered code on failure', async () => {
  const f = fixture();
  const done = f.run();
  assert.equal(f.input.value, '123456');
  assert.equal(f.verify.disabled, true);
  assert.equal(f.send.disabled, true);
  assert.equal(f.attrs.get('aria-busy'), 'true');
  assert.match(f.status().message, /Verifying/);
  f.reject(new Error('Pura email sign-in expired. Request a new code.'));
  await done;
  assert.equal(f.input.value, '123456');
  assert.equal(f.status().failed, true);
  assert.match(f.status().message, /expired/);
  assert.equal(f.verify.disabled, false);
  assert.equal(f.send.disabled, false);
  assert.equal(f.attrs.has('aria-busy'), false);
  assert.equal(f.context.oauthConnected, false);
  assert.equal(f.updates(), 1);
});

test('successful verification clears the one-time code and enables connected state', async () => {
  const f = fixture();
  const done = f.run();
  f.resolve({ connected: true, email: 'account@example.invalid' });
  await done;
  assert.equal(f.input.value, '');
  assert.equal(f.context.emailAttemptId, '');
  assert.equal(f.context.oauthConnected, true);
  assert.equal(f.verify.disabled, true);
  assert.equal(f.status().failed, false);
  assert.match(f.status().message, /Connected to Pura/);
  assert.equal(f.context.els.username.value, 'account@example.invalid');
});
