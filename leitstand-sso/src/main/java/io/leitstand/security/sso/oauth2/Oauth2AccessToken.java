/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
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
		
		public Oauth2AccessToken build() {
			try {
				assertNotInvalidated(getClass(), token);
				return token;
			} finally {
				this.token = null;
			}
		}
	}	
	
	private String accessToken;
	private String refreshToken;
	private String tokenType;
	private int expiresIn;
	
	public String getAccessToken() {
		return accessToken;
	}
	
	public String getRefreshToken() {
		return refreshToken;
	}
	
	public String getTokenType() {
		return tokenType;
	}
	
	public int getExpiresIn() {
		return expiresIn;
	}
	
}
