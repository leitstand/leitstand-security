# Leitstand Authentication Service

The _Leitstand Authentication Service_ provides support for different authentication methods to authorize Leitstand REST API calls.


## User Login Service

The user login service enables a user-agent to obtain an access token to authorize Leitstand REST API calls.
The access token is a JSON Web Token is stored in a session cookie.
The cookie name defaults to `LEITSTAND_ACCESS` and can be renamed by setting the `LEITSTAND_ACCESS_TOKEN_COOKIE_NAME` environment variable.

### OpenID/Connect Authorization Service
Leitstand can be configured to delegate user authentication to an OpenID/Connect compliant authorization service using the [OpenID Authentication Flow](https://openid.net/specs/openid-connect-basic-1_0.html#CodeFlow).

The authorization service prompts the user for credentials and assigns the [resource scopes](../leitstand-auth/README.md) the user is allowed to access to the created access token. 

Leitstand forwards the access token to the user-agent and stores a refresh-token 
for renewing expired access tokens without prompting the user for credentials again.

OpenID/Connect can be configured with the following environment variables.

| Environment Variable                      | Description                                                                                                        |
|:------------------------------------------|:-------------------------------------------------------------------------------------------------------------------|
| OIDC\_CLIENT\_ID                          | Client ID to authenticate Leitstand against the authorization service.                                             |
| OIDC\_CLIENT\_SECRET                      | Client secret to authenticate Leitstand against the authorization service.                                         |
| OIDC\_CONNECT\_TIMEOUT	                    | Connect timeout in milliseconds (Defaults to 10000).                                                               |
| OIDC\_READ\_TIMEOUT                       | Read timeout in milliseconds (Defaults to 10000).         				                                             |
| OIDC\_CONFIGURATION\_ENDPOINT				| URL to auto-discover the OpenID/Connect service endpoints and key set.                                             |

The OpenId/Connect settings can also be applied manually in case the configuration endpoint is not available:

| Environment Variable                      | Description                                                                                                        |
|:------------------------------------------|:-------------------------------------------------------------------------------------------------------------------|
| OIDC\_AUTHORIZATION\_ENDPOINT             | Authorization service URL to be used if no configuration endpoint exists.                                          |
| OIDC\_TOKEN\_ENDPOINT                     | Token service URL to be used if no configuration endpoint exists.                                                  |
| OIDC\_USERINFO\_ENDPOINT                  | OpenID user info URL to be used if no configuration endpoint exists.      											 |
| OIDC\_END\_SESSION_\ENDPOINT				| End session service URL to be used if no configuration endpoint exists.											 |
| OIDC\_JWKS\_URL					        | URL to download the trusted keys. |
| OIDC\_JWS\_ALGORITHM                      | The token signature algorithm (defaults to RS256) |

[Keycloak](keycloak.md) is an open-source identity management system that can be connected with Leitstand.

### Leitstand Authorization Service

The Leitstand built-in authorization can be used if not OpenId/Connect authorization server is available. 
It validates the user's credentials against the credentials stored in the Leitstand [user repository](../leitstand-users/README.md).

The [Leitstand UI](../leitstand-security-ui/README.md) includes views to maintain users, user roles and the resource scopes each role is allowed to access.

The Leitstand Authorization Service includes a rudimentary support for the [OpenID Authentication Flow](https://openid.net/specs/openid-connect-basic-1_0.html#CodeFlow), which allows spanning a Single-Sign On domain between Leitstand and 3rd-party products embedded in the Leitstand UI.

## Bearer Tokens

Bearer tokens are typically used to authorize a request with a [Leitstand Access Key](../leitstand-accesskeys/README.md) but Leitstand also accepts access tokens issued by the login service as bearer tokens.


## HTTP Basic Authentication (deprecated)

**It is strongly recommended to use Leitstand access keys rather than basic authentication.**

HTTP Basic Authentication support is deprecated and disabled by default.
It can be enabled by setting the `BASIC_AUTH_ENABLED` environment variable to `true`.
HTTP Basic Authentication support is limited to Leitstand Java Services, the inventory, essentially speakinkg, and very likely to be completely removed soon.

The user credentials are validated against the Leitstand user repository, even if user authentication is delegated to an OpenID/Connect-compliant authorization service. 




