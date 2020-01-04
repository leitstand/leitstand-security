# Leitstand Crypto

The _Leitstand Crypto_ library provides a bunch of cryptography utilities.

## Master Secret
The _Leitstand Master Secret_ is used to encrypt sensitive data.

The Leitstand master-secret encryption relies on the [Advanced Encryption Standard (AES)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard).

### Usage

The usage of the Leitstand master-secret is straight forward.
Simple `@Inject` the `MasterSecret` and pass the data to be encrypted or decrypted to it.

```Java
import static io.leitstand.commons.model.StringUtil.fromUtf8;
import static io.leitstand.commons.model.StringUtil.toUtf8;
...
@Inject
private MasterSecret masterSecret;
...
byte[] cipher = masterSecret.encrypt(toUtf8("Foobar"));
...
String plain = fromUtf8(masterSecret.decrypt(cipher));


```


### Master-Secret Configuration
The master-secret configuration consists of the master secret and an initialization vector (IV).


#### Master-Secret and IV Discovery

Leitstand uses the following sequence to discover the master secret and the IV.

Firstly, Leitstand checkes whether a `master.secret` file exists in the Leitstand environment directory.
If the file exsists, Leitstand reads the `master.secret` and `master.iv` properties from this file:

```Properties
master.secret=keep it
master.iv=confidential
```

Secondly, if no `master.secret` file exists, Leitstand looks up the `master.secret` and `master.iv` environment properties.

Thirdly, if no environment properties exist either, Leitstand uses _changeit_ as master secret.

#### Normalizing the Master-Secret
AES requires the secret and the IV to have a fixed length.
Leitstand, however, wanted to support an arbitrary secret length.
Hence Leitstand applies the MD5 hash function to the master secret two times and uses the first 128 bits (16 bytes) as the AES secret.

If no IV was specified, the remaining 128 bits of the twice MD5-hashed master secret is used as IV.
If an IV was specified, the same procedure as before is used to compute the AES IV:
the MD5 hash function is applied to the specified IV two times and the first 128 bit (16 byte) form the AES IV.

## Messages Authentication Code
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
The `SecureRandomFactory` provides access to a SHA1 PRNG initialized with a 440 bit seed as recommended by NIST.

## Secure Hashes
The `SecureHashes` class provides factory methods for different secure hash functions.

