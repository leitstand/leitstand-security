package io.leitstand.security.auth.jwt;

import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;

import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;

/**
 * Decodes a JSON Web Token and validates it against the matching key in the given JSON Web Key Set.
 */
public class DefaultJwksDecoder implements JwtDecoder {

    private JWTProcessor<SecurityContext> processor;
    
    /**
     * Creates a JWT decoder.
     * @param alg the JWS algorithm
     * @param keys the accepted JSON web keys
     */
    public DefaultJwksDecoder(JWSAlgorithm alg, JWK... keys) {
        this(alg, asList(keys));
    }
    
    /**
     * Creates a JWT decoder
     * @param alg the JWS algorithm
     * @param keys the accepted JSON web keys
     */
    public DefaultJwksDecoder(JWSAlgorithm alg, List<JWK> keys) {
        this(alg, new JWKSet(keys));
    }
    
    
    /**
     * Creates a JWT decoder
     * @param alg the JWS algorithm
     * @param jwks the JSON web keys
     */
    public DefaultJwksDecoder(JWSAlgorithm alg, JWKSet jwks) {
        requireNonNull(alg,"JWS algorithm is a mandatory attribute");
        requireNonNull(jwks,"JWKS is a mandatory attribute");
        processor = createJwtProcessor(alg, jwks);
        
    }

    private JWTProcessor<SecurityContext> createJwtProcessor(JWSAlgorithm alg, JWKSet jwks) {
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(alg, 
                                                                                       new ImmutableJWKSet<>(jwks));
        
        ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(keySelector);
        return processor;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public Claims decode(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            return new Claims(processor.process(jwt, null));
        } catch (Exception e) {
            throw new JwtException("Cannot decode token: "+e.getMessage(),e);
        }
    }

    /**
     * {@inheritDoc}
     */
	@Override
	public Jwt decodeToken(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWSHeader header = jwt.getHeader();
            return new Jwt(header,processor.process(jwt, null));
        } catch (Exception e) {
            throw new JwtException("Cannot decode token: "+e.getMessage(),e);
        }
	}

}
