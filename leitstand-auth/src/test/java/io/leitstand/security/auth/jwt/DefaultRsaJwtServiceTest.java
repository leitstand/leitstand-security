package io.leitstand.security.auth.jwt;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static io.leitstand.security.auth.jwt.Claims.newClaims;
import static io.leitstand.security.rsa.RsaKeys.generateRsaKeyPair;
import static java.lang.System.currentTimeMillis;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.util.Date;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import io.leitstand.security.rsa.RsaKeys;

public class DefaultRsaJwtServiceTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    
    private KeyPair keyPair;
    private DefaultRsaJwtService service;
    
    @Before
    public void initService() {
        this.keyPair = RsaKeys.generateRsaKeyPair(2048);
        this.service = new DefaultRsaJwtService(keyPair, "unit-test");
    }
    
    @Test
    public void cannot_use_non_RSA_algorithm() {
        exception.expect(IllegalArgumentException.class);
        new DefaultRsaJwtService(ES256, keyPair, "key-id");
    }

    @Test
    public void cannot_omit_algorithm() {
        exception.expect(IllegalArgumentException.class);
        new DefaultRsaJwtService(null, keyPair, "key-id");
    }

    @Test
    public void cannot_omit_keypair() {
        exception.expect(NullPointerException.class);
        new DefaultRsaJwtService(RS256, null, "key-id");
    }

    @Test
    public void cannot_omit_keyid() {
        exception.expect(NullPointerException.class);
        new DefaultRsaJwtService(RS256,keyPair, null);
    }
    
    @Test
    public void cannot_use_empty_keyid() {
        exception.expect(IllegalArgumentException.class);
        new DefaultRsaJwtService(RS256,keyPair, "");
    }
    
    @Test
    public void encode_decode_JWT() {
        Claims claims = newClaims()
                        .issuedAt(new Date())
                        .expiresAt(new Date(currentTimeMillis()+ 300000))
                        .scopes("foo bar")
                        .build();
        
        String token = service.encode(claims);
        Claims restored = service.decode(token);
        
        assertFalse(restored.isExpired());
        assertEquals(restored.getScopes(), claims.getScopes());
    }
    
    @Test
    public void decode_expired_JWT() {
        Claims claims = newClaims()
                        .issuedAt(new Date(currentTimeMillis() - 30000))
                        .expiresAt(new Date(currentTimeMillis() - 10000))
                        .scopes("foo bar")
                        .build();

        String token = service.encode(claims);
        Claims restored = service.decode(token);
        
        assertTrue(restored.isExpired());
        assertEquals(restored.getScopes(), claims.getScopes());
    }
    
    @Test
    public void invalid_JWT_signature() {
        exception.expect(JwtException.class);
        Claims claims = newClaims()
                        .issuedAt(new Date(currentTimeMillis() - 30000))
                        .expiresAt(new Date(currentTimeMillis() - 10000))
                        .scopes("foo bar")
                        .build();

        KeyPair otherKey = generateRsaKeyPair(2048);
        DefaultRsaJwtService otherService = new DefaultRsaJwtService(otherKey,"unit-test");
        
        String token = otherService.encode(claims);
        Claims restored = service.decode(token);
        
        assertTrue(restored.isExpired());
        assertEquals(restored.getScopes(), claims.getScopes());
    }
    
    @Test
    public void malformed_JWT() {
        exception.expect(JwtException.class);
        service.decode("token");
    }
    
}
