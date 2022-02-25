package io.leitstand.security.accesskeys.service;

import io.leitstand.security.auth.jwt.Jwt;


/**
 * The <code>AccessKeyValidatorService</code> allows validating an API access key token and to test whether a valid API access key has been revoked.
 */
public interface AccessKeyValidatorService {

	/**
	 * Tests whether an access key has been revoked.
	 * @param jwt the access key
	 * @return <code>true</code> if the access key is revoked, <code>false</code> if not.
	 */
	boolean isRevoked(Jwt jwt);
	
	/**
	 * Decodes and validates an access key JSON web token.
	 * @param token the access key JSON web token.
	 * @return <code>true</code> if the token signature is valid and the token has not been revoked, <code>false</code> otherwise.
	 */
	boolean isValid(String token);
	
}
