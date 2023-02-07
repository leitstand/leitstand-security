package io.leitstand.security.auth.jwt;

/**
 * A <code>JwtDecoder</code> decodes a JSON Web Token. 
 */
public interface JwtDecoder {

    
    /**
     * Decodes a JWT token and returns its associated claims.
     * Use the {@link Claims#isExpired()} method to test whether the token is expired.
     * @param jwt the JSON web token.
     * @return the claims
     * @throws JwtException if the token signature is invalid or cannot be decoded for any other reason.
     */
    Claims decode(String jwt);
    
    
    /**
     * Decodes a JWT token.
     * @param jwt the JSON web token.
     * @return the decoded web token
     * @throws JwtException if the token signature is invalid or cannot be decoded for any other reason.
     */
    Jwt decodeToken(String jwt);
    
    
}
