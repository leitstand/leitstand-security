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
package io.leitstand.security.sso.oidc;

import static io.jsonwebtoken.Jwts.parserBuilder;
import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import java.net.URI;

import javax.security.enterprise.credential.Password;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.SigningKeyResolver;
import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserName;

public class OidcConfig extends ValueObject{

	public static Builder newOpenIdConfig() {
		return new Builder();
	}

	public static class Builder {
		
		private OidcConfig config = new OidcConfig();
		
		
		public Builder withAuthorizationEndpoint(URI endpoint) {
			assertNotInvalidated(getClass(),config);
			config.authorizationEndpoint = endpoint;
			return this;
		}
		
		public Builder withUserInfoEndpoint(URI endpoint) {
			assertNotInvalidated(getClass(), config);
			config.userInfoEndpoint = endpoint;
			return this;
		}
		
		public Builder withTokenEndpoint(URI endpoint) {
			assertNotInvalidated(getClass(), config);
			config.tokenEndpoint = endpoint;
			return this;
		}
		
		public Builder withConnectTimeout(long timeout) {
			assertNotInvalidated(getClass(), config);
			config.connectTimeout = timeout;
			return this;
		}

		public Builder withReadTimeout(long timeout) {
			assertNotInvalidated(getClass(), config);
			config.readTimeout = timeout;
			return this;
		}

		public Builder withClientId(UserName clientId) {
			assertNotInvalidated(getClass(), config);
			config.clientId = clientId;
			return this;
		}
		
		public Builder withClientSecret(Password clientSecret) {
			assertNotInvalidated(getClass(), config);
			config.clientSecret = clientSecret;
			return this;
		}
		
		public Builder withSigningKeys(SigningKeyResolver keys) {
			assertNotInvalidated(getClass(),config);
			config.keys = keys;
			return this;
		}
		
		public OidcConfig build() {
			try {
				assertNotInvalidated(getClass(), config);
				return config;
			} finally {
				this.config = null;
			}
		}
	
	}
	
	private URI authorizationEndpoint;
	private URI userInfoEndpoint;
	private URI tokenEndpoint;
	private UserName clientId;
	private Password clientSecret;
	private long connectTimeout;
	private long readTimeout;
	private SigningKeyResolver keys;
	
	public URI getAuthorizationEndpoint() {
		return authorizationEndpoint;
	}
	
	public URI getUserInfoEndpoint() {
		return userInfoEndpoint;
	}
	
	public URI getTokenEndpoint() {
		return tokenEndpoint;
	}
	
	public UserName getClientId() {
		return clientId;
	}
	
	public Password getClientSecret() {
		return clientSecret;
	}
	
	public long getConnectTimeout() {
		return connectTimeout;
	}
	
	public long getReadTimeout() {
		return readTimeout;
	}

	public SigningKeyResolver getKeys() {
		return keys;
	}
	
	public Jws<Claims> parse(String jwsToken){
		JwtParser parser = parserBuilder()
						   .setSigningKeyResolver(getKeys())
						   .build();
		return parser.parseClaimsJws(jwsToken);
	}
}
