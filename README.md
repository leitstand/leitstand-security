# Leitstand Security

The _Leitstand Security_ module supports protecting Leitstand services and resources from unauthorized access.
It consists of the following sub-modules.

- The [leitstand-auth](./leitstand-auth/README.md) module contains the API to protect Leitstand resources from unauthorized access.
- The [leitstand-accesskeys](./leitstand-accesskeys/README.md) module allows maintaining access keys to establish a secure system-to-system communication.
- The [leitstand-users](./leitstand-users/README.md) module contains a user repository that is mainly used if user authorization is not delegated to an OpenID/Connect-compliant authorization service.
- The [leitstand-auth-impl](./leitstand-auth-impl/README.md) module implements the login and authorization services.
- The [leitstand-crypto](./leitstand-crypto/README.md) module contains crypotgraphy utilies to work with secure pseudo-number generators, secure hash functions, message authentication codes (MAC) and RSA keys.
- The [leitstand-security-ui](./leitstand-security-ui/README.md) module contributes user, role and access key management views to the Leitstand admin console.


