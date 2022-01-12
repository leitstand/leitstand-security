package io.leitstand.security.sso.sys.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import java.net.URI;

import io.leitstand.commons.model.ValueObject;

/**
 * The <code>SsoSettings</code> contains the URLs to the 
 * JSON Web Token Key Set (JWKS) for validation Leitstand access tokens and to 
 * the token refresh service to refresh expired access tokens.
 */
public class SsoSettings extends ValueObject{

    /**
     * Creates a <code>SsoSettings</code> builder.
     * @return a <code>SsoSettings</code> builder.
     */
    public static Builder newSsoSettings() {
        return new Builder();
    }
    
    /**
     * SsoSettings builder.
     */
    public static class Builder {
        
        private SsoSettings config = new SsoSettings();
        
        /**
         * Sets the token service endpoint URL.
         * @param tokenEndpoint the token service URL.
         * @return a reference to this builder to continue object creation
         */
        public Builder withTokenEndpoint(URI tokenEndpoint) {
            assertNotInvalidated(getClass(), config);
            config.tokenEndpoint = tokenEndpoint;
            return this;
        }

        /**
         * Sets the JWKS download URL.
         * @param jwksUri the URL to download the JSON Web Key Set.
         * @return a reference to this builder to continue with object creation
         */
        public Builder withJwksUri(URI jwksUri) {
            assertNotInvalidated(getClass(), config);
            config.jwksUri = jwksUri;
            return this;
        }

        /**
         * Creates an immutable <code>SsoSettings</code> object.
         * Subsequent calls to this build method raise an exception.
         * @return the immutable <code>SsoSettings</code> object.
         */
        public SsoSettings build() {
            try {
                assertNotInvalidated(getClass(), config);
                return config;
            } finally {
                this.config = null;
            }
        }
        
    }
    
    private URI tokenEndpoint;
    private URI jwksUri;
    
    /**
     * Returns the token service endpoint URL.
     * @return the token service endpoint URL.
     */
    public URI getTokenEndpoint() {
        return tokenEndpoint;
    }
    
    /**
     * Returns the JSON Web Key Set download URL.
     * @return the JSON Web Key Set download URL.
     */
    public URI getJwksUri() {
        return jwksUri;
    }
    
}