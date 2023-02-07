# Leitstand Access Keys

_Leitstand Access Keys_ grant permanent access to the Leitstand REST API unless the access key has been revoked. 

Access keys grant access to the [resource scopes](../leitstand-auth/README.md) being selected when the access key was created. 
An access key is _immutable_ and its name and assigned scopes cannot be changed. 

The access key is a JSON Web Token and signed with the _RS256_ algorithm. 
The key ID is `api-access`.
The access key must be send as `Bearer` token in the `Authorization` HTTP header to authorize HTTP request with an Leitstand access key.

The private key to sign API access keys is read from the _LEITSTAND_HOME/api.pem_ file.
Leitstand creates a 2048-bit RSA key pair and stores it in the _LEISTAND_HOME/api.pem_ file in case the _api.pem_ file does not exist.

The API.pem file contains the RSA private key followed by its public key in X509 format.

```PEM
-----BEGIN RSA PRIVATE KEY-----
... private key ...
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
... public key ...
-----END CERTIFICATE-----
```



Access keys can be maintained in the Leitstand User Interface or through the Leitstand REST API.
 
The [Leitstand user interface](../leitstand-security-ui/README.md) lists all issued access keys and allows creating new and revoking existing access keys. 
In addition the user interface includes a validator to test whether a JSON Web Token is a valid Leitstand access key.
The validator also allows restoring an accidentally revoked access key.

