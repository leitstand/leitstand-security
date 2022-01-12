# Leitstand Authentication Framework

The _Leitstand Authentication Framework_ provides a simple framework to authenticate Leitstand requests.

## Authentication Extension Points

The _Leitstand Authentication Framework_ defines two main extension points, the `LoginManager` and the `AccessTokenManager`.
The `LoginManager` validates user-password credentials and issues an access token to authenticate subsequent requests, 
unless the credentials were invalid.
An `AccessTokenManager` validates an access token and rejects requests with an invalid access tokens.


## Access Keys
The [leitstand-accesskeys](../leitstand-accesskeys/README.md) and [leitstand-accesskeys-validation](../leitstand-accesskeys-validation/README.md) projects
provide access keys support for inter-system authentication. 

## JSON Web Token
The authentication framework issues a JSON Web Token (JWT) when valid  credentials are send to the `/api/v1/login` endpoint:

```JSON
{"user_id":"admin",
 "password":"changeit"}
```

The JWT is stored in a cookie to authenticate subsequent requests.

The default [Login Manager](../leitstand-login/README.md) validates the credentials against the [Leitstand User Repository](../leitstand-users/README.md).

## HTTP Basic Authentication
In HTTP Basic Authentication the `Authorization` HTTP request header conveys the Base64-encoded user password credentials to authenticate a request.

Leitstand decodes the `Authorization` header and verifies the provided credentials.
Leitstand sends a `401 Unauthorized` reply if the credentials are invalid.

Basic authentication is handy for instant authentication of `curl` commands.
However, since the credentials are not encrypted by any means it is highly recommended to use basic authentication rarely.