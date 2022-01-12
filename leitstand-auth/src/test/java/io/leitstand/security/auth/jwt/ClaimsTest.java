package io.leitstand.security.auth.jwt;

import static io.leitstand.security.auth.jwt.Claims.newClaims;
import static io.leitstand.testing.ut.LeitstandCoreMatchers.hasSizeOf;
import static io.leitstand.testing.ut.LeitstandCoreMatchers.isEmptyList;
import static io.leitstand.testing.ut.LeitstandCoreMatchers.isEmptySet;
import static java.lang.System.currentTimeMillis;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.Date;

import org.junit.Test;

import io.leitstand.security.auth.jwt.Claims;

public class ClaimsTest {

    
    @Test
    public void empty_scopes() {
        Claims claims = newClaims().build();
        assertThat(claims.getScopes(), isEmptySet());
        assertFalse(claims.hasScope("scope"));
    }
    
    @Test
    public void empty_audience() {
        Claims claims = newClaims().build();
        assertThat(claims.getAudience(), isEmptyList());
        assertFalse(claims.hasAudience("audience"));
    }
    
    @Test
    public void audience_match() {
        Claims claims = newClaims()
                .audience("audience")
                .build();
        assertThat(claims.getAudience(),hasSizeOf(1));
        assertTrue(claims.hasAudience("audience"));
    }
    
    @Test
    public void create_claims_with_scope() {
        Claims claims = newClaims()
                        .scopes("a b c")
                        .build();
        assertThat(claims.getScopes(),hasSizeOf(3));
        assertTrue(claims.hasScope("a"));
        assertTrue(claims.hasScope("b"));
        assertTrue(claims.hasScope("c"));
        assertFalse(claims.hasScope("d"));
    }
    
    @Test
    public void has_claim_requires_at_least_one_match() {
        Claims claims = newClaims()
                .scopes("a b")
                .build();
        assertThat(claims.getScopes(),hasSizeOf(2));
        assertTrue(claims.hasScope("a","b"));
        assertTrue(claims.hasScope("b","c"));
        assertTrue(claims.hasScope("a","c"));
        assertFalse(claims.hasScope("c","d"));
    }
    
    @Test
    public void claim_is_expired() {
        Claims claims = newClaims()
                        .expiresAt(new Date(currentTimeMillis() - 1000))
                        .build();
        assertTrue(claims.isExpired());

    }
}
