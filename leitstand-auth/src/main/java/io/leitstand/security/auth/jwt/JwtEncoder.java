package io.leitstand.security.auth.jwt;

/**
 * A <code>JwtEncoder</code> encodes a JSON Web Token.
 */
public interface JwtEncoder {


    /**
     * Encodes a JSON Web Token.
     * @param claims the JWT claims.
     * @return the encoded JWT in compact code.
     */
    String encode(Claims claims);
 
    
}
