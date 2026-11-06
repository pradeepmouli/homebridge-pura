import { AuthenticationDetails, CognitoUser, CognitoUserPool } from 'amazon-cognito-identity-js';
import { HomebridgePluginUiServer, RequestError } from '@homebridge/plugin-ui-utils';

import { DEFAULT_USER_POOL_ID, DEFAULT_CLIENT_ID } from '../dist/authConfig.js';
import { PuraOAuthSession } from '../dist/oauth.js';

class UiServer extends HomebridgePluginUiServer {
  constructor() {
    super();

    const oauth = new PuraOAuthSession(this.homebridgeStoragePath);
    this.onRequest('/oauth/start', () => oauth.start());
    this.onRequest('/oauth/status', () => oauth.status());
    this.onRequest('/oauth/email/status', () => oauth.emailStatus());
    this.onRequest('/oauth/email/start', async payload => {
      if (typeof payload?.email !== 'string' || payload.email.length > 254) {
        throw new RequestError('Enter your existing Pura account email address.');
      }
      try {
        return await oauth.startEmail(payload.email);
      } catch (error) {
        throw new RequestError(error.message);
      }
    });
    this.onRequest('/oauth/email/verify', async payload => {
      if (typeof payload?.attemptId !== 'string' || payload.attemptId.length > 128
        || typeof payload?.code !== 'string' || payload.code.length !== 6) {
        throw new RequestError('Enter the six-digit code from your Pura email.');
      }
      try {
        return await oauth.verifyEmail(payload.attemptId, payload.code);
      } catch (error) {
        throw new RequestError(error.message);
      }
    });
    this.onRequest('/oauth/website', async payload => {
      if (typeof payload?.refreshValue !== 'string' || payload.refreshValue.length > 16384) {
        throw new RequestError('Paste the __prt cookie value from pura.com.');
      }
      try {
        return await oauth.connectWebsite(payload.refreshValue);
      } catch (error) {
        throw new RequestError(error.message);
      }
    });
    this.onRequest('/oauth/complete', async payload => {
      if (typeof payload?.callbackUrl !== 'string' || payload.callbackUrl.length > 16384) {
        throw new RequestError('Paste the complete Pura callback URL.');
      }
      try {
        return await oauth.complete(payload.callbackUrl);
      } catch (error) {
        throw new RequestError(error.message);
      }
    });
    this.onRequest('/test-credentials', this.handleTestCredentials.bind(this));

    this.ready();
  }

  async handleTestCredentials(payload) {
    const username = typeof payload?.username === 'string' ? payload.username.trim() : '';
    const password = typeof payload?.password === 'string' ? payload.password : '';

    if (!username || !password) {
      throw new RequestError('Username and password are required.', { code: 'MISSING_FIELDS' });
    }

    const userPool = new CognitoUserPool({
      UserPoolId: DEFAULT_USER_POOL_ID,
      ClientId: DEFAULT_CLIENT_ID,
    });

    const authenticationDetails = new AuthenticationDetails({
      Username: username,
      Password: password,
    });

    const cognitoUser = new CognitoUser({
      Username: username,
      Pool: userPool,
    });

    return await new Promise((resolve, reject) => {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: () => {
          resolve({
            ok: true,
            message: 'Authentication succeeded.',
          });
        },
        onFailure: (error) => {
          const message = error?.message || 'Authentication failed.';
          reject(new RequestError(message, {
            code: 'AUTH_FAILED',
          }));
        },
      });
    });
  }
}

(() => {
  return new UiServer();
})();
