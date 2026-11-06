/** Public Pura app-client settings, confirmed through its OIDC discovery and Apple login redirect. */
export const DEFAULT_USER_POOL_ID = 'us-east-1_LaB718hYv';
export const DEFAULT_CLIENT_ID = '4iekubat0jb5iljfbaalsiqf9j';
export const OAUTH_ISSUER = `https://cognito-idp.us-east-1.amazonaws.com/${DEFAULT_USER_POOL_ID}`;
export const OAUTH_DOMAIN = 'https://auth.pura.co';
export const OAUTH_REDIRECT_URI = 'pura://callback';
export const WEBSITE_REFRESH_URL = 'https://user.trypura.io/v1/auth/refresh';
