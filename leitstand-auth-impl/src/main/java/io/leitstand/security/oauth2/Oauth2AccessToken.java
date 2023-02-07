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
package io.leitstand.security.oauth2;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import io.leitstand.commons.model.ValueObject;

/**
 * An Oauth2 Access Token as it is returned by an OAuth2 compliant token service.
 */
public class Oauth2AccessToken extends ValueObject{

    /**
     * Creates a <code>Oauth2AccessToken</code> builder.
     * @return a <code>Oauth2AccessToken</code> builder.
     */
    public static Builder newOauth2AccessToken() {
		return new Builder();
	}
		
    /**
     * A builder to create an immutable <code>Oauth2AccessToken</code>.
     */
	public static class Builder {
		
		private Oauth2AccessToken token = new Oauth2AccessToken();

		/**
		 * Sets the encoded ID token
		 * @param idToken the ID token
		 * @return a reference to this builder to continue with the token creation
		 */
		public Builder withIdToken(String idToken) {
			assertNotInvalidated(getClass(), token);
			token.idToken = idToken;
			return this;
		}


        /**
         * Sets the encoded access token
         * @param accessToken the access token
         * @return a reference to this builder to continue with the token creation
         */
		public Builder withAccessToken(String accessToken) {
			assertNotInvalidated(getClass(), token);
			token.accessToken = accessToken;
			return this;
		}
		
		

        /**
         * Sets the encoded refresh token
         * @param refreshToken the refresh token
         * @return a reference to this builder to continue with the token creation
         */
		public Builder withRefreshToken(String refreshToken) {
			assertNotInvalidated(getClass(), token);
			token.refreshToken = refreshToken;
			return this;
		}
		
		

        /**
         * Sets the token type name.
         * @param tokenType the token type
         * @return a reference to this builder to continue with the token creation
         */
		public Builder withTokenType(String tokenType) {
			assertNotInvalidated(getClass(), token);
			token.tokenType = tokenType;
			return this;
		}

        /**
         * Sets the access token time-to-live (TTL) in seconds.
         * @param ttl the access token TTL
         * @return a reference to this builder to continue with the token creation
         */
		public Builder withExpiresIn(int ttl) {
			assertNotInvalidated(getClass(), token);
			token.expiresIn = ttl;
			return this;
		}

        /**
         * Sets the refresh token time-to-live (TTL) in seconds.
         * @param ttl the refresh token TTL
         * @return a reference to this builder to continue with the token creation
         */	
		public Builder withRefreshExpiresIn(int ttl) {
			assertNotInvalidated(getClass(), token);
			token.refreshExpiresIn = ttl;
			return this;
		}
		
		/**
		 * Creates the <code>Oauth2AccessToken</code> and invalidates this builder.
		 * Subsequent calls of the <code>build()</code> method raise an exception.
		 * @return the immutable <code>Oauth2AccessToken</code>.
		 */
		public Oauth2AccessToken build() {
			try {
				assertNotInvalidated(getClass(), token);
				return token;
			} finally {
				this.token = null;
			}
		}
	}	
	
	private String idToken;
	private String accessToken;
	private String refreshToken;
	private String tokenType;
	private int expiresIn;
	private int refreshExpiresIn;
	
	
	/**
	 * Returns the encoded access token.
	 * @return the encoded access token.
	 */
	public String getAccessToken() {
		return accessToken;
	}
	
	/**
	 * Returns the encoded refresh token.
	 * @return the encoded refresh token.
	 */
	public String getRefreshToken() {
		return refreshToken;
	}
	
	/**
	 * Returns the encoded ID token.
	 * @return the encoded ID token.
	 */
	public String getIdToken() {
		return idToken;
	}
	
	/**
	 * Returns the token type name.
	 * @return the token type name.
	 */
	public String getTokenType() {
		return tokenType;
	}
	
	/**
	 * Returns the access token time-to-live (TTL) in seconds.
	 * @return the access token TTL in seconds.
	 */
	public int getExpiresIn() {
		return expiresIn;
	}
	
	/**
	 * Returns the refresh token time-to-live (TTL) in seconds.
	 * @return the refresh token TTL in seconds.
	 */
	public int getRefreshExpiresIn() {
		return refreshExpiresIn;
	}
	
}
