package io.leitstand.security.auth.jwt;

import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static io.leitstand.security.auth.jwt.Claims.newClaims;
import static io.leitstand.security.rsa.RsaKeys.generateRsaKeyPair;
import static java.lang.System.currentTimeMillis;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.nimbusds.jose.jwk.RSAKey;

import io.leitstand.security.auth.jwt.Claims;
import io.leitstand.security.auth.jwt.DefaultJwksDecoder;
import io.leitstand.security.auth.jwt.DefaultRsaJwtService;
import io.leitstand.security.auth.jwt.JwtEncoder;
import io.leitstand.security.auth.jwt.JwtException;

public class DefaultJwksDecoderTest {
    
    private static final String KEY_0 = "k0";
    private static final String KEY_1 = "k1";
    
    @Rule
    public ExpectedException exception = ExpectedException.none();

    private DefaultJwksDecoder decoder;
    private JwtEncoder encoder;
    
    @Before
    public void initDecoder() {
        KeyPair p0 = generateRsaKeyPair(2048);
        KeyPair p1 = generateRsaKeyPair(2048);
        
        
        RSAKey k0 = new RSAKey.Builder((RSAPublicKey)p0.getPublic()).keyID(KEY_0).build();
        RSAKey k1 = new RSAKey.Builder((RSAPublicKey)p1.getPublic()).keyID(KEY_1).build();
        
        decoder = new DefaultJwksDecoder(RS256, k0,k1);
        encoder = new DefaultRsaJwtService(p0, KEY_0); 
    }
    

    @Test
    public void accept_token_with_key_from_keyset() {
        String token = encoder.encode(newClaims().build());
        Claims claims = decoder.decode(token);
        assertNotNull(claims);
        assertFalse(claims.isExpired());
    }
    
    @Test
    public void accept_expired_token_with_key_from_keyset() {
        Claims expired = newClaims().expiresAt(new Date(currentTimeMillis() - 1000)).build();
        String token = encoder.encode(expired);
        Claims claims = decoder.decode(token);
        assertTrue(claims.isExpired());
        
    }
    
    @Test
    public void reject_token_with_unknown_key() {
        exception.expect(JwtException.class);
        JwtEncoder encoder2 = new DefaultRsaJwtService(generateRsaKeyPair(2048), "other-key");
        String token = encoder2.encode(newClaims().build());
        decoder.decode(token);
    }
    
}
