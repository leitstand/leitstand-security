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
package io.leitstand.security.sso.oidc.config;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.security.sso.oidc.ReasonCode.OID0006E_INVALID_ACCESS_TOKEN;
import static java.util.Objects.requireNonNull;

import java.net.URI;
import java.util.concurrent.TimeUnit;

import javax.enterprise.inject.Typed;
import javax.security.enterprise.credential.Password;

import com.nimbusds.jose.jwk.JWKSet;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.jwt.Claims;
import io.leitstand.security.auth.jwt.JwtDecoder;
import io.leitstand.security.auth.jwt.JwtException;

/**
 * The OpenID/Connect server configuration.
 */
@Typed()
public class OidcConfig {

    /**
     * Creates a builder for an immutable OpenID/Connect server configuration.
     * @return a builder for an immutable OpenID/Connect server configuration.
     */
	public static Builder newOpenIdConfig() {
		return new Builder();
	}

	/**
	 * A builder for an immutable OpenID/Connect server configuration.
	 */
	public static class Builder {
		
		private OidcConfig config = new OidcConfig();
		
		
		/**
		 * Sets the issuer name.
		 * @param issuer the issuer name
		 * @return a reference to this builder to continue with the object creation
		 */
		public Builder withIssuer(String issuer) {
		    assertNotInvalidated(getClass(), config);
		    config.issuer = issuer;
		    return this;
		}
		
		/**
		 * Sets the authorization endpoint URL.
		 * @param endpoint the authorization endpoint URL
		 * @return a reference to this builder to continue with the object creation
		 */
		public Builder withAuthorizationEndpoint(URI endpoint) {
			assertNotInvalidated(getClass(),config);
			config.authorizationEndpoint = endpoint;
			return this;
		}

		/**
         * Sets the user-info endpoint URL.
         * @param endpoint the user-info endpoint URL
         * @return a reference to this builder to continue with the object creation
         */
		public Builder withUserInfoEndpoint(URI endpoint) {
			assertNotInvalidated(getClass(), config);
			config.userInfoEndpoint = endpoint;
			return this;
		}
		
		
	    /**
         * Sets the token endpoint URL.
         * @param endpoint the token endpoint URL
         * @return a reference to this builder to continue with the object creation
         */
		public Builder withTokenEndpoint(URI endpoint) {
			assertNotInvalidated(getClass(), config);
			config.tokenEndpoint = endpoint;
			return this;
		}
		
		/**
         * Sets the end-session endpoint URL.
         * @param endpoint the end-session endpoint URL
         * @return a reference to this builder to continue with the object creation
         */	
		public Builder withEndSessionEndpoint(URI endpoint) {
			assertNotInvalidated(getClass(), config);
			config.endSessionEndpoint = endpoint;
			return this;
		}

	    /**
         * Sets the connect timeout
         * @param timeout the connect timeout
         * @param unit the connect timeout unit
         * @return a reference to this builder to continue with the object creation
         */
		public Builder withConnectTimeout(long timeout, TimeUnit unit) {
			assertNotInvalidated(getClass(), config);
			config.connectTimeoutMillis = unit.toMillis(timeout);
			return this;
		}

		/**
         * Sets the read timeout
         * @param timeout the read timeout
         * @param unit the read timeout unit
         * @return a reference to this builder to continue with the object creation
         */
		public Builder withReadTimeout(long timeout, TimeUnit unit) {
			assertNotInvalidated(getClass(), config);
			config.readTimeoutMillis = unit.toMillis(timeout);
			return this;
		}

		/**
         * Sets the client ID used for authenticating requests to the OpenID/Connect server.
         * @param clientId the client identifier
         * @return a reference to this builder to continue with the object creation
         */
		public Builder withClientId(UserName clientId) {
			assertNotInvalidated(getClass(), config);
			config.clientId = clientId;
			return this;
		}

        /**
         * Sets the client secret used for authenticating requests to the OpenID/Connect server.
         * @param clientSecret the client secret
         * @return a reference to this builder to continue with the object creation
         */
		public Builder withClientSecret(Password clientSecret) {
			assertNotInvalidated(getClass(), config);
			config.clientSecret = clientSecret;
			return this;
		}
		
		/**
		 * Sets the access key decoder.
		 * @param decoder the access key decoder.
		 * @return a reference to this builder to continue with object creation
		 */
        public Builder withDecoder(JwtDecoder decoder) {
            assertNotInvalidated(getClass(), config);
            config.decoder = decoder;
            return this;
        }

        
		/**
		 * Sets the key set used to validate the access key.
		 * @param keySet the trusted keys
		 * @return a reference to this builder to continue with object creation
		 */
        public Builder withKeySet(JWKSet keySet) {
        	assertNotInvalidated(getClass(),config);
        	config.keySet = keySet;
        	return this;
        }
		
		/**
		 * Creates an immutable OpenID/Connect configuration and invalidates this builder.
		 * Subsequent calls to the <code>build()</code> method will raise an exception.
		 * @return the OpenID/Connect configuration
		 */
		public OidcConfig build() {
			try {
				assertNotInvalidated(getClass(), config);
				requireNonNull(config.keySet,"KeySet must not be null");
				requireNonNull(config.decoder,"Decoder must not be null");
				return config;
			} finally {
				this.config = null;
			}
		}


	
	}
	
	private String issuer;
	private URI authorizationEndpoint;
	private URI userInfoEndpoint;
	private URI tokenEndpoint;
	private URI endSessionEndpoint;
	private UserName clientId;
	private Password clientSecret;
	private long connectTimeoutMillis;
	private long readTimeoutMillis;
	private JwtDecoder decoder;
	private JWKSet keySet;
	
	/**
	 * Returns the authorization endpoint URL.
	 * @return the authorization endpoint URL.
	 */
	public URI getAuthorizationEndpoint() {
		return authorizationEndpoint;
	}
	
	/**
	 * Returns the user-info endpoint URL.
	 * @return the user-info endpoint URL.
	 */
	public URI getUserInfoEndpoint() {
		return userInfoEndpoint;
	}
	
	/**
	 * Returns the token endpoint URL.
	 * @return the token endpoint URL.
	 */
	public URI getTokenEndpoint() {
		return tokenEndpoint;
	}
	
	/**
	 * Returns the end-session endpoint URL.
	 * @return the end-session endpoint URL.
	 */
	public URI getEndSessionEndpoint() {
		return endSessionEndpoint;
	}
	
	/**
	 * Returns the client identifier.
	 * @return the client identifier.
	 */
	public UserName getClientId() {
		return clientId;
	}
	
	/**
	 * Returns the client secret.
	 * @return the client secret.
	 */
	public Password getClientSecret() {
		return clientSecret;
	}
	
	/**
	 * Return the connect timeout in milliseconds.
	 * @return the connect timeout in milliseconds.
	 */
	public long getConnectTimeoutMillis() {
		return connectTimeoutMillis;
	}
	
	/**
	 * Returns the read timeout in milliseconds.
	 * @return the read timeout in milliseconds.
	 */
	public long getReadTimeoutMillis() {
		return readTimeoutMillis;
	}

	/**
	 * Parses a signed JWT token and extract all claims if the token signature is valid.
	 * @param jwt the signed JWT
	 * @return the extracted claims.
	 */
	public Claims decodeAccessToken(String jwt){
	    // Create verifier from keyset
	    try {
	        return decoder.decode(jwt);
	    } catch (JwtException e) {
	        throw new AccessDeniedException(e,OID0006E_INVALID_ACCESS_TOKEN);
	    }
	}

	/**
	 * Returns the issuer name used in the issued access tokens.
	 * @return the access token issuer name.
	 */
    public String getIssuer() {
        return issuer;
    }

	public JWKSet getKeySet() {
		return keySet;
	}
    
}
