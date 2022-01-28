# Leitstand Crypto

The _Leitstand Crypto_ library provides a set of cryptography utilities.

## Master Secret
The `MasterSecret` uses the [Advanced Encryption Standard (AES] 128 bit in [CTR mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CTR) for encrypting and decrypting data.
The master secret is read from the _LEITSTAND_HOME/master.secret_ file and must base Base64-encoded. 
Leitstand computes the [SHA3-256](https://en.wikipedia.org/wiki/SHA-3) hash from the configured secret 
and uses the lower 16 bytes as key and the upper 16 bytes as IV.

The `MasterSecret` is a CDI-managed bean and the usage is straight forward.

```Java

@Inject
private MasterSecret secret;

// Encrypt plaintext
byte[] ciphertext  = secret.encrypt("plaintext");

// Decrypt ciphertext
String plaintext = new String(secret.decrypt(ciphertext))
```

## RSA Keys

The `RsaKeys` utility allows reading RSA keys from PEM files, generating RSA key pairs and exporting RSA key pairs in PEM format. 

## Message Authentication Codes
The `MessageAuthenticationCodes` class provides utility functions for MAC computation.

```Java
import static io.leitstand.security.mac.MessageCodes.sign;
import static io.leitstand.security.mac.MessageCodes.isValid;

// Compute HMAC for a specified message.
Secret secret = ...
String message = "message";
byte[] mac = hmacSha256(secret).sign(message);

// Validate HMAC for a given message
boolean valid = hmacSha256(secret).isValid(message,mac);
```

## Secure PRNG
The `SecureRandomFactory` provides access to a SHA1 pseudo-random number generator (RPNG) initialized with a 440 bit seed as recommended by NIST.

## Secure Hashes
The `SecureHashes` class provides factory methods for different secure hash functions, which can then be used to compute the respective hashes.

