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
package io.leitstand.security.sso.oauth2;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import io.leitstand.commons.model.ValueObject;

public class Oauth2AccessToken extends ValueObject{

	public static Builder newOauth2AccessToken() {
		return new Builder();
	}
		
	public static class Builder {
		
		private Oauth2AccessToken token = new Oauth2AccessToken();
		
		public Builder withIdToken(String idToken) {
			assertNotInvalidated(getClass(), token);
			token.idToken = idToken;
			return this;
		}
		
		public Builder withAccessToken(String accessToken) {
			assertNotInvalidated(getClass(), token);
			token.accessToken = accessToken;
			return this;
		}
		
		public Builder withRefreshToken(String refreshToken) {
			assertNotInvalidated(getClass(), token);
			token.refreshToken = refreshToken;
			return this;
		}
		
		public Builder withTokenType(String tokenType) {
			assertNotInvalidated(getClass(), token);
			token.tokenType = tokenType;
			return this;
		}
		
		public Builder withExpiresIn(int ttl) {
			assertNotInvalidated(getClass(), token);
			token.expiresIn = ttl;
			return this;
		}
		
		public Builder withRefreshExpiresIn(int ttl) {
			assertNotInvalidated(getClass(), token);
			token.refreshExpiresIn = ttl;
			return this;
		}
		
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
	
	public String getAccessToken() {
		return accessToken;
	}
	
	public String getRefreshToken() {
		return refreshToken;
	}
	
	public String getIdToken() {
		return idToken;
	}
	
	public String getTokenType() {
		return tokenType;
	}
	
	public int getExpiresIn() {
		return expiresIn;
	}
	
	public int getRefreshExpiresIn() {
		return refreshExpiresIn;
	}
	
}
