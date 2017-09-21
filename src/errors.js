import VError from 'verror';

export class OAuth2ClientError extends VError { }

export class OAuth2ClientUsageError extends OAuth2ClientError { }
export class OAuth2ClientRuntimeError extends OAuth2ClientError { }

export class ClientIdRequired extends OAuth2ClientUsageError {
  get message() { return 'a client id is required for this operation but has not been set'; };
}

export class IllegalParameters extends OAuth2ClientUsageError { }

export class UnexpectedProviderError extends OAuth2ClientRuntimeError { }
export class InvalidRequest extends OAuth2ClientRuntimeError { }
export class InvalidClient extends OAuth2ClientRuntimeError { }
export class InvalidGrant extends OAuth2ClientRuntimeError { }
export class UnauthorizedClient extends OAuth2ClientRuntimeError { }
export class UnsupportedGrantType extends OAuth2ClientRuntimeError { }
export class InvalidScope extends OAuth2ClientRuntimeError { }
