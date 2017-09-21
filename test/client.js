import chai, { assert, expect } from 'chai';
import chaiString from 'chai-string';
import nock from 'nock';
import { parse as parseQueryString } from 'qs';

import { Errors, OAuth2Client } from '../src';

const ACCESS_TOKEN = 'accessToken';
const AUTHORIZATION_CODE = 'NICE_MARMOT';
const AUTHORIZATION_CODE_BAD = 'SUDDENLY_GARY_BUSEY';
const CLIENT_ID = 'testClient';
const CLIENT_ID_CRAPPY = 'crappyClient';
const CLIENT_ID_POWERLESS = 'powerlessClient';
const CLIENT_ID_UNKNOWN = 'unknownClient';
const EXPIRES_IN = 3600;
const PROVIDER_BASE_URL = 'https://oauth2.grandbudapest.hotel';
const PROVIDER_AUTHORIZE_PATH = '/authorize';
const PROVIDER_TOKEN_PATH = '/token';
const PROVIDER_NO_GRANT_TOKEN_PATH = '/no-grant-token';
const PROVIDER_AUTHORIZE_ENDPOINT = `${PROVIDER_BASE_URL}${PROVIDER_AUTHORIZE_PATH}`;
const PROVIDER_TOKEN_ENDPOINT = `${PROVIDER_BASE_URL}${PROVIDER_TOKEN_PATH}`;
const PROVIDER_NO_GRANT_TOKEN_ENDPOINT = `${PROVIDER_BASE_URL}${PROVIDER_NO_GRANT_TOKEN_PATH}`;
const REDIRECT_URI = 'https://zombo.com';
const REFRESH_TOKEN = 'refreshToken';
const SCOPE1 = 'aScope';
const SCOPE2 = 'bScope';
const SCOPE_BAD = 'BAD_SCOPE';
const TOKEN_TYPE = 'FAUX';

const CLIENT_PARAMS_PROVIDER_NO_GRANT = {
  authorizeEndpoint: PROVIDER_AUTHORIZE_ENDPOINT,
  tokenEndpoint: PROVIDER_NO_GRANT_TOKEN_ENDPOINT,
  clientId: CLIENT_ID,
  redirectUri: REDIRECT_URI,
};
const CLIENT_PARAMS_MADE_CRAPPY = {
  authorizeEndpoint: PROVIDER_AUTHORIZE_ENDPOINT,
  tokenEndpoint: PROVIDER_TOKEN_ENDPOINT,
  clientId: CLIENT_ID_CRAPPY,
  redirectUri: REDIRECT_URI,
};
const CLIENT_PARAMS_POWERLESS_CLIENT = {
  authorizeEndpoint: PROVIDER_AUTHORIZE_ENDPOINT,
  tokenEndpoint: PROVIDER_TOKEN_ENDPOINT,
  clientId: CLIENT_ID_POWERLESS,
  redirectUri: REDIRECT_URI,
}
const CLIENT_PARAMS_UNKNOWN_CLIENT = {
  authorizeEndpoint: PROVIDER_AUTHORIZE_ENDPOINT,
  tokenEndpoint: PROVIDER_TOKEN_ENDPOINT,
  clientId: CLIENT_ID_UNKNOWN,
  redirectUri: REDIRECT_URI,
};
const CLIENT_PARAMS_WITH_REDIRECT = {
  authorizeEndpoint: PROVIDER_AUTHORIZE_ENDPOINT,
  tokenEndpoint: PROVIDER_TOKEN_ENDPOINT,
  clientId: CLIENT_ID,
  redirectUri: REDIRECT_URI,
};
const CLIENT_PARAMS_WITHOUT_REDIRECT = {
  authorizeEndpoint: PROVIDER_AUTHORIZE_ENDPOINT,
  tokenEndpoint: PROVIDER_TOKEN_ENDPOINT,
  clientId: CLIENT_ID,
};

chai.use(chaiString);

describe('OAuth 2.0 client', function () {

  let clientMadeCrappy = null;
  let clientPowerless = null;
  let clientProviderNoGrant = null;
  let clientUnknown = null;
  let clientWithRedirect = null;
  let clientWithoutRedirect = null;

  beforeEach(function() {
    clientMadeCrappy = new OAuth2Client(CLIENT_PARAMS_MADE_CRAPPY);
    clientPowerless = new OAuth2Client(CLIENT_PARAMS_POWERLESS_CLIENT);
    clientProviderNoGrant = new OAuth2Client(CLIENT_PARAMS_PROVIDER_NO_GRANT);
    clientUnknown = new OAuth2Client(CLIENT_PARAMS_UNKNOWN_CLIENT);
    clientWithRedirect = new OAuth2Client(CLIENT_PARAMS_WITH_REDIRECT);
    clientWithoutRedirect = new OAuth2Client(CLIENT_PARAMS_WITHOUT_REDIRECT);
    nock(PROVIDER_BASE_URL)
      .defaultReplyHeaders({
        'Content-Type': 'application/json',
      })
      .post(PROVIDER_TOKEN_PATH, { scope: SCOPE_BAD })
      .reply(400, {
        error: 'invalid_scope',
        error_description: 'fake failure',
        error_uri: 'https://wherever',
      })
      .post(PROVIDER_TOKEN_PATH, function(body) {
        const { grant_type, code, client_id, redirect_uri, scope } = body;
        const numParams = Object.keys(body).length;
        const result =
          (numParams <= 4 && numParams >= 3)
          && client_id === CLIENT_ID
          && (grant_type === 'authorization_code' && code === AUTHORIZATION_CODE)
          && (redirect_uri === REDIRECT_URI || redirect_uri == null)
          && !scope || scope.indexOf(SCOPE_BAD) < 0;
        return result;
      })
      .reply(200, {
        access_token: ACCESS_TOKEN,
        refresh_token: REFRESH_TOKEN,
        expires_in: EXPIRES_IN,
        token_type: TOKEN_TYPE,
      })
      .post(PROVIDER_TOKEN_PATH, { client_id: CLIENT_ID_CRAPPY })
      .reply(400, {
        error: 'invalid_request',
        error_description: 'fake failure',
        error_uri: 'https://wherever',
      })
      .post(PROVIDER_TOKEN_PATH, { client_id: CLIENT_ID_POWERLESS })
      .reply(400, {
        error: 'unauthorized_client',
        error_description: 'fake failure',
        error_uri: 'https://wherever',
      })
      .post(PROVIDER_TOKEN_PATH, { client_id: CLIENT_ID_UNKNOWN })
      .reply(400, {
        error: 'invalid_client',
        error_description: 'fake failure',
        error_uri: 'https://wherever',
      })
      .post(PROVIDER_TOKEN_PATH, { code: AUTHORIZATION_CODE_BAD })
      .reply(400, {
        error: 'invalid_grant',
        error_description: 'fake failure',
        error_uri: 'https://wherever',
      })
      .post(PROVIDER_NO_GRANT_TOKEN_PATH,)
      .reply(400, {
        error: 'unsupported_grant_type',
        error_description: 'fake failure',
        error_uri: 'https://wherever',
      });
  });

  it('should throw IllegalParameters if token retrieval is attempted without a grant', async function () {
    let worked = false;
    try {
      await clientWithRedirect.getToken();
    } catch (err) {
      expect(err).to.be.an.instanceof(Errors.IllegalParameters);
      worked = true;
    }
    assert(worked, 'expected to throw IllegalParameters');
  });

  describe('authorization code grant', function () {

    it('should construct a valid authorization request url without redirect uri and without scope', async function () {
      const authorizeUrl = await clientWithoutRedirect.getAuthorizationCodeRequestUrl();
      expect(authorizeUrl).startsWith(`${PROVIDER_AUTHORIZE_ENDPOINT}?`);
      const authorizeQueryString = parseQueryString(authorizeUrl.substring(PROVIDER_AUTHORIZE_ENDPOINT.length + 1));
      expect(Object.keys(authorizeQueryString).length).to.equal(3);
      expect(authorizeQueryString.response_type).to.equal('code');
      expect(authorizeQueryString.client_id).to.equal(CLIENT_ID);
      expect(authorizeQueryString.state).to.be.a('string');
      expect(authorizeQueryString.state).to.match(/^[a-zA-Z0-9]{32,}$/);
    });

    it('should construct a valid authorization request url without redirect uri and with a single scope', async function () {
      const authorizeUrl = await clientWithoutRedirect.getAuthorizationCodeRequestUrl({ scopes: [SCOPE1] });
      expect(authorizeUrl).startsWith(`${PROVIDER_AUTHORIZE_ENDPOINT}?`);
      const authorizeQueryString = parseQueryString(authorizeUrl.substring(PROVIDER_AUTHORIZE_ENDPOINT.length + 1));
      expect(Object.keys(authorizeQueryString).length).to.equal(4);
      expect(authorizeQueryString.response_type).to.equal('code');
      expect(authorizeQueryString.client_id).to.equal(CLIENT_ID);
      expect(authorizeQueryString.state).to.be.a('string');
      expect(authorizeQueryString.state).to.match(/^[a-zA-Z0-9]{32,}$/);
      expect(authorizeQueryString.scope).to.equal(SCOPE1);
    });

    it('should construct a valid authorization request url without redirect uri and with multiple scopes', async function () {
      const authorizeUrl = await clientWithoutRedirect.getAuthorizationCodeRequestUrl({ scopes: [SCOPE1, SCOPE2] });
      expect(authorizeUrl).startsWith(`${PROVIDER_AUTHORIZE_ENDPOINT}?`);
      const authorizeQueryString = parseQueryString(authorizeUrl.substring(PROVIDER_AUTHORIZE_ENDPOINT.length + 1));
      expect(Object.keys(authorizeQueryString).length).to.equal(4);
      expect(authorizeQueryString.response_type).to.equal('code');
      expect(authorizeQueryString.client_id).to.equal(CLIENT_ID);
      expect(authorizeQueryString.state).to.be.a('string');
      expect(authorizeQueryString.state).to.match(/^[a-zA-Z0-9]{32,}$/);
      expect(authorizeQueryString.scope).to.equal(`${SCOPE1} ${SCOPE2}`);
    });

    it('should construct a valid authorization request url with redirect uri and without scope', async function () {
      const authorizeUrl = await clientWithRedirect.getAuthorizationCodeRequestUrl();
      expect(authorizeUrl).startsWith(`${PROVIDER_AUTHORIZE_ENDPOINT}?`);
      const authorizeQueryString = parseQueryString(authorizeUrl.substring(PROVIDER_AUTHORIZE_ENDPOINT.length + 1));
      expect(Object.keys(authorizeQueryString).length).to.equal(4);
      expect(authorizeQueryString.response_type).to.equal('code');
      expect(authorizeQueryString.client_id).to.equal(CLIENT_ID);
      expect(authorizeQueryString.state).to.be.a('string');
      expect(authorizeQueryString.state).to.match(/^[a-zA-Z0-9]{32,}$/);
      expect(authorizeQueryString.redirect_uri).to.equal(REDIRECT_URI);
    });

    it('should construct a valid authorization request url with redirect uri and a single scope', async function () {
      const authorizeUrl = await clientWithRedirect.getAuthorizationCodeRequestUrl({ scopes: [SCOPE1] });
      expect(authorizeUrl).startsWith(`${PROVIDER_AUTHORIZE_ENDPOINT}?`);
      const authorizeQueryString = parseQueryString(authorizeUrl.substring(PROVIDER_AUTHORIZE_ENDPOINT.length + 1));
      expect(Object.keys(authorizeQueryString).length).to.equal(5);
      expect(authorizeQueryString.response_type).to.equal('code');
      expect(authorizeQueryString.client_id).to.equal(CLIENT_ID);
      expect(authorizeQueryString.state).to.be.a('string');
      expect(authorizeQueryString.state).to.match(/^[a-zA-Z0-9]{32,}$/);
      expect(authorizeQueryString.scope).to.equal(SCOPE1);
      expect(authorizeQueryString.redirect_uri).to.equal(REDIRECT_URI);
    });

    it('should construct a valid authorization request url with redirect uri and multiple scopes', async function () {
      const authorizeUrl = await clientWithRedirect.getAuthorizationCodeRequestUrl({ scopes: [SCOPE1, SCOPE2] });
      expect(authorizeUrl).startsWith(`${PROVIDER_AUTHORIZE_ENDPOINT}?`);
      const authorizeQueryString = parseQueryString(authorizeUrl.substring(PROVIDER_AUTHORIZE_ENDPOINT.length + 1));
      expect(Object.keys(authorizeQueryString).length).to.equal(5);
      expect(authorizeQueryString.response_type).to.equal('code');
      expect(authorizeQueryString.client_id).to.equal(CLIENT_ID);
      expect(authorizeQueryString.state).to.be.a('string');
      expect(authorizeQueryString.state).to.match(/^[a-zA-Z0-9]{32,}$/);
      expect(authorizeQueryString.scope).to.equal(`${SCOPE1} ${SCOPE2}`);
      expect(authorizeQueryString.redirect_uri).to.equal(REDIRECT_URI);
    });

    it('should exchange an authorization code for a token when redirect not provided', async function () {
      const { accessToken, refreshToken, expiresIn, tokenType } = await clientWithoutRedirect.getToken({ code: AUTHORIZATION_CODE });
      expect(accessToken).to.equal(ACCESS_TOKEN);
      expect(refreshToken).to.equal(REFRESH_TOKEN);
      expect(expiresIn).to.equal(EXPIRES_IN);
      expect(tokenType).to.equal(TOKEN_TYPE);
    });

    it('should exchange an authorization code for a token when redirect provided', async function () {
      const { accessToken, refreshToken, expiresIn, tokenType } = await clientWithRedirect.getToken({ code: AUTHORIZATION_CODE });
      expect(accessToken).to.equal(ACCESS_TOKEN);
      expect(refreshToken).to.equal(REFRESH_TOKEN);
      expect(expiresIn).to.equal(EXPIRES_IN);
      expect(tokenType).to.equal(TOKEN_TYPE);
    });

    it('should throw InvalidRequest if invalid_request is received', async function () {
      let worked = false;
      try {
        await clientMadeCrappy.getToken({ code: AUTHORIZATION_CODE });
      } catch (err) {
        expect(err).to.be.an.instanceof(Errors.InvalidRequest);
        worked = true;
      }
      assert(worked, 'expected to throw InvalidRequest');
    });

    it('should throw InvalidClient if invalid_client is received', async function () {
      let worked = false;
      try {
        await clientUnknown.getToken({ code: AUTHORIZATION_CODE });
      } catch (err) {
        expect(err).to.be.an.instanceof(Errors.InvalidClient);
        worked = true;
      }
      assert(worked, 'expected to throw InvalidClient');
    });

    it('should throw InvalidGrant if invalid_grant is received', async function () {
      let worked = false;
      try {
        await clientWithRedirect.getToken({ code: AUTHORIZATION_CODE_BAD });
      } catch (err) {
        expect(err).to.be.an.instanceof(Errors.InvalidGrant);
        worked = true;
      }
      assert(worked, 'expected to throw InvalidGrant');
    });

    it('should throw UnauthorizedClient if unauthorized_client is received', async function () {
      let worked = false;
      try {
        await clientPowerless.getToken({ code: AUTHORIZATION_CODE });
      } catch (err) {
        expect(err).to.be.an.instanceof(Errors.UnauthorizedClient);
        worked = true;
      }
      assert(worked, 'expected to throw UnauthorizedClient');
    });

    it('should throw UnsupportedGrantType if unsupported_grant_type is received', async function () {
      let worked = false;
      try {
        await clientProviderNoGrant.getToken({ code: AUTHORIZATION_CODE });
      } catch (err) {
        expect(err).to.be.an.instanceof(Errors.UnsupportedGrantType);
        worked = true;
      }
      assert(worked, 'expected to throw UnsupportedGrantType');
    });

  });

  describe('implicit grant', function () {

    before(function() {
      client = new OAuth2Client();
    });

    it('should construct a valid authorization request url', async function () {
      assert(false, 'test has not been implemented');
    });

  });

  describe('resource owner password credential grant', function () {

    before(function() {
      client = new OAuth2Client();
    });

    it('should construct a valid authorization request url', async function () {
      assert(false, 'test has not been implemented');
    });

  });

  describe('client credentials grant', function () {

    before(function() {
      client = new OAuth2Client();
    });

    it('should construct a valid authorization request url', async function () {
      assert(false, 'test has not been implemented');
    });

  });

  describe('extension grant', function () {

    before(function() {
      client = new OAuth2Client();
    });

    it('should construct a valid authorization request url', async function () {
      assert(false, 'test has not been implemented');
    });

  });

});
