/*
 * Copyright 2020 RtBrick Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.leitstand.security.sso.standalone.config;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.security.sso.standalone.ReasonCode.SOL0002E_CANNOT_SIGN_ACCESS_TOKEN;
import static io.leitstand.security.sso.standalone.ReasonCode.SOL0003E_INVALID_ACCESS_TOKEN;
import static java.lang.String.format;
import static java.util.logging.Logger.getLogger;

import java.time.Duration;
import java.util.logging.Logger;

import javax.enterprise.inject.Typed;

import com.nimbusds.jose.jwk.JWKSet;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.security.auth.jwt.Claims;
import io.leitstand.security.auth.jwt.JwtException;
import io.leitstand.security.auth.jwt.JwtService;


/**
 * The <code>StandaloneLoginConfig</code> configures the Leitstand login settings when 
 * login is not delegated to an OpenID/Connect authorization service.
 */
@Typed()
public class StandaloneLoginConfig {
    
    private static final Logger LOG = getLogger(StandaloneLoginConfig.class.getName());

    public static final String STANDALONE_LOGIN_KEY_ID = "standalone-login";

    
    /**
     * Creates a new <code>StandaloneLoginConfig</code> builder.
     * @return a new <code>StandaloneLoginConfig</code> builder.
     */
    public static Builder newStandaloneLoginConfig() {
        return new Builder();
    }
    
    /**
     * A builder for immutable <code>StandaloneLoginConfig</code> value objects.
     */
    public static class Builder {
        
        private StandaloneLoginConfig config = new StandaloneLoginConfig();

        /**
         * Sets the access token time-to-live.
         * @param ttl the time-to-live duration
         * @return a reference to this builder to continue with object creation
         */
        public Builder withTimeToLive(Duration ttl) {
            assertNotInvalidated(getClass(), config);
            config.jwtTtl = ttl;
            return this;
        }

        /**
         * Sets the grace period when an access can be refreshed.
         * @param refresh the refresh duration
         * @return a reference to this builder to continue with object creation
         */
        public Builder withRefresh(Duration refresh) {
            assertNotInvalidated(getClass(), config);
            config.jwtRefresh = refresh;
            return this;
        }
        
        /**
         * Sets the service to verify a Leitstand access token.
         * @param service the JWT verification service
         * @return a reference to this builder to continue with object creation
         */
        public Builder withJwtService(JwtService service) {
            assertNotInvalidated(getClass(), config);
            config.jwtService = service;
            return this;
        }
        
        
        /**
         * Sets the set of trusted keys.
         * @param keySet the set of trusted keys
         * @return a reference to this builder to continue with object creation
         */
        public Builder withKeySet(JWKSet keySet) {
        	assertNotInvalidated(getClass(), keySet);
        	config.keySet = keySet;
        	return this;
        }
        
        /**
         * Returns an immutable <code>StandaloneLoginConfig</code> and invalidates this builder.
         * Subsequent calls of the <code>build()</code> method raises an exception.
         * @return the immutable <code>StandaloneLoginConfig</code> value object.
         */
        public StandaloneLoginConfig build() {
            try {
                assertNotInvalidated(getClass(), config);
                return config;
            } finally {
                config = null;
            }
        }
        
    }
    
    private Duration jwtTtl = Duration.ofSeconds(3600);
	private Duration jwtRefresh = Duration.ofSeconds(300);
    private JwtService jwtService;
    private JWKSet keySet;

    
    /**
     * Decodes a serialized access token.
     * @param token the serialized access token
     * @return the access token claims.
     * @throws AccessDeniedException when the access token is invalid.
     */
    public Claims decodeAccessToken(String token){
        try {
            return jwtService.decode(token);
        } catch (JwtException e) {
            throw new AccessDeniedException(e, SOL0003E_INVALID_ACCESS_TOKEN);
        }
    }

    /**
     * Creates a signed JSON Web Token from the given access token claims.
     * @param claims the access token claims
     * @return the serialized JSON Web Token.
     */
    public String signAccessToken(Claims.Builder claims) {
        return signAccessToken(claims.build());
    }
    
    /**
     * Creates a signed JSON Web Token from the given access token claims.
     * @param claims the access token claims
     * @return the serialized JSON Web Token.
     */
    public String signAccessToken(Claims claims) {
        try {
            return jwtService.encode(claims);
        } catch (JwtException e) {
            LOG.fine(() -> format("%: Cannot sign access token: %s", 
                                  SOL0002E_CANNOT_SIGN_ACCESS_TOKEN.getReasonCode(),
                                  e.getMessage()));
            throw new StandaloneLoginConfigException(e, SOL0002E_CANNOT_SIGN_ACCESS_TOKEN);
        }
    }
	
    /**
     * Returns the access token time-to-live duration.
     * @return the access token time-to-live duration.
     */
	public Duration getTimeToLive() {
		return jwtTtl;
	}

	/**
	 * Returns the access token refresh interval.
	 * @return the access token refresh interval.
	 */
	public Duration getRefreshInterval() {
		return jwtRefresh;
	}
	
	/**
	 * Returns the set of trusted keys.
	 * @return the set of trusted keys.
	 */
	public JWKSet getKeySet() {
	    return keySet;
	}
	
}
