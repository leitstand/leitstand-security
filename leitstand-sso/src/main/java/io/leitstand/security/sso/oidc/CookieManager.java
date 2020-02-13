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

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.security.auth.UserId.userId;
import static java.lang.System.currentTimeMillis;
import static java.util.Arrays.stream;
import static java.util.Collections.emptySet;
import static java.util.stream.Collectors.toSet;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

import java.util.Set;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.leitstand.security.auth.UserId;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.http.AccessTokenManager;
import io.leitstand.security.auth.http.UserContextProvider;
import io.leitstand.security.sso.oauth2.Oauth2AccessToken;
import io.leitstand.security.sso.oauth2.RefreshTokenStore;

@Dependent
public class CookieManager implements AccessTokenManager{

	private static final String JWT_COOKIE = getSystemProperty("LEITSTAND_ACCESS_TOKEN_COOKIE_NAME","LEITSTAND_ACCESS");
	

	static Cookie findAccessToken(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		// Cookies is null, if request sends no cookie information
		if(cookies == null) {
			return null;
		}
		for(Cookie cookie:cookies) {
			if(cookie.getName().equals(JWT_COOKIE)) {
				return cookie;
			}
		}
		return null;
	}
	
	@Inject
	private OidcClient client;
	
	@Inject
	private RefreshTokenStore refreshTokens;
	
	@Inject
	private OidcConfig oidcConfig;
	
	@Inject
	private UserContextProvider userContext;
	
	@Override
	public CredentialValidationResult validateAccessToken(HttpServletRequest request, HttpServletResponse response) {
		// Validate access token
		Cookie jwsCookie = findAccessToken(request);
		// TODO Lookup idCookie and try to resolve access key from a local cache.
		if(jwsCookie == null) {
			return NOT_VALIDATED_RESULT;
		}
		
		// Verify
		Jws<Claims> jws = oidcConfig.parse(jwsCookie.getValue());
		
		if(isExpired(jws)) {
			String sub = jws.getBody().getSubject();
			String refreshToken = refreshTokens.getRefreshToken(sub);
			Oauth2AccessToken oauth2 = client.refreshAccessToken(refreshToken);
			refreshTokens.storeRefreshToken(sub, oauth2.getRefreshToken());
			jwsCookie.setValue(oauth2.getAccessToken());
			jwsCookie.setMaxAge(oauth2.getExpiresIn());
			jwsCookie.setHttpOnly(true);
			response.addCookie(jwsCookie);
			jws = oidcConfig.parse(oauth2.getAccessToken());
		}
		UserId userId =  userId(jws.getBody().getSubject());
		Set<String> scopes = stream(jws.getBody().get("scope",String.class).split("\\s+")).collect(toSet()); 
		UserName userName = UserName.userName(jws.getBody().get("preferred_username",String.class));
		String name = jws.getBody().get("name",String.class);
		
		userContext.setUserId(userId);
		userContext.setUserName(userName);
		userContext.setScopes(scopes);
		userContext.setName(name);
		userContext.seal();
		
		
		return new CredentialValidationResult(userContext.getUserName().toString(),
											  emptySet());
	}
	
	private boolean isExpired(Jws<Claims> jws) {
		return currentTimeMillis() > jws.getBody().getExpiration().getTime();
	}
	
}
