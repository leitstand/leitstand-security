package io.leitstand.security.auth.jwt;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * A <code>JwtService</code> combines a {@link JwtDecoder} and a {@link JwtEncoder}.
 */
public interface JwtService extends JwtDecoder, JwtEncoder{

    
}