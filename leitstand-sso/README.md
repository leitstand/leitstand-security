# Leitstand Single Sign-On

Leitstand Single Sign-On (SSO) relies on the [OpenID Authentication Flow](https://openid.net/specs/openid-connect-basic-1_0.html#CodeFlow).

## Connecting Leitstand to an OpenId Identity Provider

The table below summarizes the _Leitstand OpenID Connect (OIDC) settings_:

| Property                                  | Description                                                                                                        |
|:------------------------------------------|:-------------------------------------------------------------------------------------------------------------------|
| OIDC\_CLIENT\_ID                          | Client ID to authenticate against the authorization service.                                                       |
| OIDC\_CLIENT\_SECRET                      | Client secret to authenticate against the authorization service.                                                   |
| OIDC\_CONNECT\_TIMEOUT	                    | Connect timeout in milliseconds (Defaults to 10000).                                                               |
| OIDC\_READ\_TIMEOUT                       | Read timeout in milliseconds (Defaults to 10000).         				                                             |
| OIDC\_CONFIGURATION\_ENDPOINT				| URL to discover service endpoints and key information.                                                             |
| OIDC\_AUTHORIZATION\_ENDPOINT             | Authorization service URL to be used if no configuration endpoint exists.                                          |
| OIDC\_TOKEN\_ENDPOINT                     | Token service URL to be used if no configuration endpoint exists.                                                  |
| OIDC\_USERINFO\_ENDPOINT                  | OpenID user info URL to be used if no configuration endpoint exists.      											 |
| OIDC\_TOKEN\_X5C						    | Base64 URL-encoded X509 certificate chain to verify JWS tokens if the certificate chain cannot be auto-discovered. |
| OIDC\_TOKEN\_SECRET						| Token secret to verify a JWS if the secret cannot be auto-discovered.                                              |

The OIDC\_TOKEN\_X5C and the OIDC\_TOKEN\_SECRET can be specified at the same time. 
Leitstand selects the proper settings depending on the algorithm declared in the JWS header.

The settings are read from the `<LEITSTAND_ETC_ROOT>/sso.properties` file or from environment variables.
The environment variables override the properties file in case of a conflicting configuration.

The client secret and the token secret can be protected by the [Leitstand Master Secret](../leitstand-crypto/README.md).

See the [keycloak example configuration](./doc/keycloak.md) for a full OpenID Identity Provider and OAuth-based authorization setup.