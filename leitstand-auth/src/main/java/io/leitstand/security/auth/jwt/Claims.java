package io.leitstand.security.auth.jwt;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static java.lang.System.currentTimeMillis;
import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.Collections.emptySet;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toSet;

import java.util.Date;
import java.util.List;
import java.util.Set;

import com.nimbusds.jwt.JWTClaimsSet;

/**
 * JSON Web Token claims.
 */
public class Claims {

    /**
     * Creates a builder for an immutable Claims object.
     * @return a builder for an immutable Claims object.
     */
    public static Builder newClaims() {
        return new Builder();
    }
    
    /**
     * Claims object builder.
     */
    public static class Builder {
        
        private JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder();
        
        /**
         * Sets the JWT ID (jti).
         * @param jti the JWT ID
         * @return a reference to this builder to continue object creation
         */
        public Builder jwtId(String jti) {
            assertNotInvalidated(getClass(), claims);
            claims.jwtID(jti);
            return this;
        }

        
        /**
         * Sets the JWT subject (sub).
         * @param sub the JWT subject
         * @return a reference to this builder to continue object creation
         */
        public Builder subject(String sub) {
            assertNotInvalidated(getClass(), claims);
            claims.subject(sub);
            return this;
        }
        
        /**
         * Sets the scopes, separated by blanks, as single string.
         * @param scopes the scopes
         * @return a reference to this builder to continue object creation.
         */
        public Builder scopes(String scopes) {
            assertNotInvalidated(getClass(), claims);
            claims.claim("scope", scopes.trim());
            return this;
        }
        
        /**
         * Sets the scopes.
         * @param scopes the scopes
         * @return a reference to this builder to continue object creation.
         */
        public Builder scopes(Set<String> scopes) {
            return scopes(scopes
                          .stream()
                          .collect(joining(" ")));
        }
        
        /**
         * Sets the name claim.
         * @param name the name
         * @return a reference to this builder to continue object creation.
         */
        public Builder name(String name) {
            assertNotInvalidated(getClass(), claims);
            claims.claim("name", name.trim());
            return this;            
        }
        
        /**
         * Sets the JWT issue date (iat).
         * @param iat the "issued at" date
         * @return a reference to this builder to continue object creation.
         */
        public Builder issuedAt(Date iat) {
            assertNotInvalidated(getClass(), claims);
            claims.issueTime(iat);
            return this;
        }
        
        /**
         * Sets the JWT expiration date (exp).
         * @param exp the expiration date
         * @return a reference to this builder to continue object creation
         */
        public Builder expiresAt(Date exp) {
            assertNotInvalidated(getClass(), claims);
            claims.expirationTime(exp);
            return this;
        }
        
        /**
         * Adds a custom claim.
         * @param name the claim name
         * @param value the claim value
         * @return a reference to this builder to continue object creation.
         */
        public Builder claim(String name, String value) {
            assertNotInvalidated(getClass(), claims);
            claims.claim(name, value);
            return this;
        }
        
        /**
         * Sets the JWT audience (aud). 
         * @param aud the audience
         * @return a reference to this builder to continue object creation.
         */
        public Builder audience(String... aud) {
            assertNotInvalidated(getClass(), claims);
            claims.audience(asList(aud));
            return this;
        }
        
        /**
         * Returns the immutable JWT claims and invalidates this builder.
         * Subsequent calls of the build method raise an exception.
         * @return the immutable JWT claims.
         */
        public Claims build() {
            assertNotInvalidated(getClass(), claims);
            try {
                return new Claims(claims.build());
            } finally {
                claims = null;
            }
        }

    }
    
    private JWTClaimsSet claims;
    
    
    protected Claims(JWTClaimsSet claims) {
        this.claims = claims;
    }

    /**
     * Returns the scopes associated with this JWT claims.
     * Returns an empty set if no scopes are associated.
     * @return the scopes associated with this JWT claims.
     */
    public Set<String> getScopes(){
        String scopes = (String) claims.getClaim("scope");
        if (scopes == null || scopes.isEmpty()) {
            return emptySet();
        }
        return stream(scopes.split("\\s")).collect(toSet());
    }
    
    /**
     * Returns <code>true</code> if the JWT token claims contains at least one of the specified scopes. 
     * @param scopes expected scopes
     * @return <code>true</code> if this JWT token claims contains at least one of the specified scopes.
     */
    public boolean hasScope(String... scopes) {
        Set<String> claimsScopes = getScopes();
        for (String scope : scopes) {
            if (claimsScopes.contains(scope)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Returns <code>true</code> if the JWT token claims audiences includes the given audience.
     * @param audience the audience name
     * @return <code>true</code> if the JWT token claims audiences includes the given audience.
     */
    public boolean hasAudience(String audience) {
        return getAudience().contains(audience);
    }
    
    /**
     * Returns the creation date of the JWT token.
     * @return the JWT creation date.
     */
    public Date getIssuedAt() {
        return claims.getIssueTime();
    }
    
    /**
     * Returns the expiration date of the JWT token.
     * @return the JWT expiration date.
     */
    public Date getExpiresAt() {
        return claims.getExpirationTime();
    }
    
    /**
     * Returns whether this JWT token is expired or not.
     * @return <code>true</code> when the token is expired, <code>false</code> if not.
     */
    public boolean isExpired() {
        Date exp = claims.getExpirationTime();
        if (exp != null) {
            return exp.getTime() < currentTimeMillis();
        }
        return false;
    }

    JWTClaimsSet getClaims() {
        return claims;
    }
    
    @Override
    public String toString() {
        return claims.toString();
    }

    /**
     * Returns the JWT subject.
     * @return the JWT subject.
     */
    public String getSubject() {
        return claims.getSubject();
    }

    /**
     * Returns the JWT ID.
     * @return the JWT ID.
     */
    public String getJwtId() {
        return claims.getJWTID();
    }

    
    /**
     * Returns a custom claim value.
     * @param name the claim name
     * @return the claim value or <code>null</code> if the claim does not exist
     */
    public String getClaim(String name) {
        return (String) claims.getClaim(name);
    }

    
    /**
     * Returns the audiences list.
     * @return the audiences list.
     */
    public List<String> getAudience() {
        return claims.getAudience();
    }
}
