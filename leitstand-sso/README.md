# Leitstand Single Sign-On

Leitstand Single Sign-On (SSO) relies on the [OpenID Authentication Flow](https://openid.net/specs/openid-connect-basic-1_0.html#CodeFlow).

## Connecting Leitstand to an OpenId Identity Provider

The table below summarizes the _Leitstand OpenID Connect (OIDC) settings_:

| Property                                  | Description                                               |
|:------------------------------------------|:----------------------------------------------------------|
| OIDC\_AUTHORIZATION\_ENDPOINT             | Authorization service URL.                                |
| OIDC\_TOKEN\_ENDPOINT                     | Token service URL.                                        |
| OIDC\_USERINFO\_ENDPOINT                  | OpenID user info URL.                                     |
| OIDC\_CLIENT\_ID                          | Client ID to authenticate token request.                  |
| OIDC\_CLIENT\_SECRET                      | Client secret to authenticate token request.              |
| OIDC\_READ\_TIMEOUT                       | Read timeout in milliseconds (Defaults to 10000).         |
| OIDC\_CONNECT\_TIMEOUT	                | Connect timeout in milliseconds (Defaults to 10000).          |
| OIDC\_ROLES\_CLAIM                        | Name of an optional custom roles claim.                   |
| OIDC\_ROLE\_<OIDC_ROLE> 					| Maps the <OIDC_ROLE> to the role with the specified name. |

The settings are read from the `<LEITSTAND_ETC_ROOT>/sso.properties` file or from environment variables.
The environment variables override the properties file in case of a conflicting configuration.

The client secret can be protected by the [Leitstand Master Secret](../leitstand-crypto/README.md).

The standard _OpenID User Profile_ does not include a _roles_ claim, 
whereas some of the OpenID identity providers supply a custom claim to transmit the user's roles as part of the user information.
The `OIDC_ROLES_CLAIM` property sets the name of a custom roles claim.
The role mapping allows to map a received role to a Leitstand role. 
If a custom roles claim is set, Leitstand reads all roles from the user info for which a mapping exists.

The user's roles are configured in Leitstand if the identity providers lacks a custom roles claim support.

See the [keycloak example configuration](./doc/keycloak.md) for a full OpenID Identity Provider connection setup.

 





 











