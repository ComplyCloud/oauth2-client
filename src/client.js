import { Random } from '@complycloud/cryptonomicon';
import createDebugger from 'debug';
import fetchPonyFill from 'fetch-ponyfill';

import { Errors } from '.';
import pkg from '../package.json';

const VERSION = pkg.version;
const REPO_URL = pkg.repository;
const USER_AGENT = `ComplyCloud-OAuth2Client/${VERSION} (+${REPO_URL})`;

const debug = createDebugger('complycloud:oauth2-client');
const { fetch } = fetchPonyFill();

/** Generates an oauth2 token request payload when using the authorization code grant type */
function tokenWithCodePayload({ code, clientId, redirectUri }) {
  const payload = { grant_type: 'authorization_code', code, client_id: clientId };
  if (redirectUri) payload.redirect_uri = redirectUri;
  return payload;
}

/** Generates an oauth2 token request payload when using the resource owner password credentials grant type */
function tokenWithPasswordPayload({ username, password, clientId, redirectUri }) {
  return {};
}

/** Isomorphic method of compiling url-encoded form data for oauth2 post requests */
function getFormData(payload) {
  if (typeof window !== 'undefined') return new URLSearchParams(payload);
  const { URLSearchParams } = require('url');
  return new URLSearchParams(payload);
}

/** Represents an OAuth 2.0 client */
export default class OAuth2Client {

  /** Create an OAuth 2.0 client */
  constructor({ authorizeEndpoint, tokenEndpoint, clientId, redirectUri } = {}) {
    this.authorizeEndpoint = authorizeEndpoint;
    this.tokenEndpoint = tokenEndpoint;
    this.clientId = clientId;
    this.redirectUri = redirectUri;
  }

  /**
   * Reset the state to a new value.
   * @param {string} state - An externally-generated state, defaults to a secure random 32-bit string
   */
  async resetState(state) {
    this.state = state || await Random.alphaNumericString(32);
  }

  /** Creates an OAuth 2.0 authorization request url when initiating an authorization code grant request */
  async getAuthorizationCodeRequestUrl({ scopes } = {}) {
    const { authorizeEndpoint, clientId, redirectUri } = this;
    let url = `${authorizeEndpoint}?response_type=code`;
    if (clientId == null) throw new Errors.ClientIdRequired();
    url += `&client_id=${encodeURIComponent(clientId)}`;
    if (redirectUri != null) url += `&redirect_uri=${encodeURIComponent(redirectUri)}`;
    if (scopes != null) {
        if (!Array.isArray(scopes)) throw new Errors.IllegalParameters('scopes must be an array of requested scopes');
        url += `&scope=${encodeURIComponent(scopes.join(' '))}`;
    }
    await this.resetState();
    url += `&state=${encodeURIComponent(this.state)}`;
    debug('constructed authorization request url %s', url);
    return url;
  }

  /** Creates an OAuth 2.0 authorization request url when initiating an implicit grant request */
  async getImplicitGrantRequestUrl({ scopes } = {}) {
    throw new Error('unimplemented');
  }

  /** Retrieves an access token using either an authorization code or resource owner password credentials */
  async getToken({ code, username, password, autoRefresh = false, scopes } = {}) {
    const { clientId, redirectUri, tokenEndpoint } = this;
    if ((code && (username || password)) || (!code && !username)) {
      throw new Errors.IllegalParameters('must provide authorization code OR username/password');
    }
    const requestPayload = !!code
      ? tokenWithCodePayload({ code, clientId, redirectUri })
      : tokenWithPasswordPayload({ username, password, scopes, clientId, redirectUri });
      try {
        const response = await fetch(tokenEndpoint, {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'User-Agent': USER_AGENT,
          },
          body: getFormData(requestPayload),
        });
        const responsePayload = await response.json();
        const {
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: expiresIn,
          token_type: tokenType,
          scope: scopesString,
          error,
          error_description: errorDescription,
          error_uri: errorUri,
        } = responsePayload;
        let errMsg = `${errorDescription}`;
        if (errorUri) errMsg += ` (${errorUri})`;
        switch (error) {
          case undefined:
          case null:
            return {
              accessToken,
              refreshToken,
              expiresIn,
              tokenType,
              scope: !!scopesString ? scopesString.split(' ') : undefined,
            };
          case 'invalid_request':
            throw new Errors.InvalidRequest(errMsg);
          case 'invalid_client':
            throw new Errors.InvalidClient(errMsg);
          case 'invalid_grant':
            throw new Errors.InvalidGrant(errMsg);
          case 'unauthorized_client':
            throw new Errors.UnauthorizedClient(errMsg);
          case 'unsupported_grant_type':
            throw new Errors.UnsupportedGrantType(errMsg);
          case 'invalid_scope':
            throw new Errors.InvalidScope(errMsg);
          default:
            throw new Errors.UnexpectedProviderError(`Unknown provider error "${error}": "${errMsg}"`);
        }
      } catch (err) {
        if (err instanceof Errors.OAuth2ClientError) throw err;
        throw new Errors.UnexpectedProviderError(err, 'provider failed in an unexpected manner');
      }
  }

}
