# Leitstand Access Key Validation

This project contains the Leitstand default access key encoding and validation implementation.
The access key validation can be replaced by a custom implementation, while still using the 
[Leitstand Access Key Management](../leitstand-accesskeys/README.md).

## Access Key Encoding

Leitstand applies the following sequence to create a bearer token from an access key:

1. All information conveyed with the access key is concatenated into a single string using a colon (`:`) as delimiter.
2. A HMAC-SHA256 is computed over the created string.
3. The Base64-encoded HMAC is added to the token using again a colon (`:`) as delimiter.
4. The signed token get Base64-encoded.

Access key decoding is executes the same procedure in reverse order:
1. The bearer token is read from the HTTP `Authorization` header.
2. The bearer token gets Base64-decoded.
3. The token payload and HMAC value gets separated.
4. The payload HMAC-SHA256 value is compared with the token HMAC.
   The token is valid if the HMAC value is equal.
   
## Access Token Secret

The access token secret is either read from the `jwt.properties` file in the Leitstand environment 

```Properties
# jwt.properties 
# Access Token Secret protected by the Leitstand Master Secret
jwt.secret=aGdiZqelR+xoigY8ebb/LLrKEDdAGRG7+bRWOLKoH+eLQCa8mLuV5cZ7bmfxuJgm
```

or from the `jwt.secret` environment property. 
The `jwt.secret` value is protected by the [Leitstand master secret](../leitstand-crypto/README.md).

The access token secret defaults to _lab-environment_ if unspecified.

   