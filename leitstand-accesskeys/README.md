# Leitstand Access Keys

_Leitstand Access Keys_ are used to authenticate inter-system communication.

## Access Keys at a Glance

A _Leitstand Access Key_ has a unique ID in UUIDv4 format, a unique name and an optional description that explains why the access key was issued.

The scope of an access key can be restricted to certain HTTP methods and/or certain REST API paths. 
This allows to create an access key for readonly access to element information, for example.

Access keys are digitally signed and encrypted.

## REST API Authentication

Leitstand creates an access key token, whenever a new access key was created.
This token must be added as _bearer token_ to HTTP request `Authorization` header to authenticate a request.

```HTTP
Authorization: Bearer <TOKEN>
```

## Access Key Lifecycle
An access key never expires but can be revoked.
Any attempt to access Leitstand with an revoked access key is rejected with a `401 Unauthorized` response.

Leitstand never stores an issued access key token but only the access key metadata:
- UUID, the unique access key ID
- Name, the unique access key name
- Description, the optional access key description
- HTTP method constraints,
- REST API path constraints.

Only the description of an issued access key can be updated.
All other changes requires to revoke the existing access keys and to create a new access key.

## Access Key Validation

The _Leitstand Access Key Validation_ is a two-step process.
The first step is to validate the access token signature.
The second step is to verify that the access key has not been revoked. 
An access key has been revoked when the access key ID is unknown to Leitstand.

The access key encoding, including the digital signing, and decoding default implementation has been moved to the [leitstand-accesskeys-validation](../leitstand-accesskeys-validation/README.md) project.
This allows to customize the access key encoding and validation algorithm, while still leveraging the Leitstand built-in access key management.