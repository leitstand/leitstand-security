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
import static io.leitstand.security.auth.UserName.userName;
import static java.lang.String.format;
import static java.lang.System.currentTimeMillis;
import static java.net.URLEncoder.encode;
import static java.util.Arrays.stream;
import static java.util.Collections.emptySet;
import static java.util.concurrent.TimeUnit.SECONDS;
import static java.util.logging.Level.FINE;
import static java.util.stream.Collectors.toSet;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

import java.util.Date;
import java.util.Set;
import java.util.logging.Logger;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.leitstand.commons.AccessDeniedException;
import io.leitstand.security.auth.UserId;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.http.AccessTokenManager;
import io.leitstand.security.auth.http.LoginConfiguration;
import io.leitstand.security.auth.http.UserContextProvider;
import io.leitstand.security.sso.oauth2.Oauth2AccessToken;
import io.leitstand.security.sso.oauth2.RefreshTokenStore;

@Dependent
public class CookieManager implements AccessTokenManager{

	private static final Logger LOG = Logger.getLogger(CookieManager.class.getName());
	
	private static final String JWT_COOKIE = getSystemProperty("LEITSTAND_ACCESS_TOKEN_COOKIE_NAME","LEITSTAND_ACCESS");
	private static final String ID_COOKIE  = getSystemProperty("LEITSTAND_ID_TOKEN","LEITSTAND_ID");
	

	static Cookie findAccessToken(HttpServletRequest request) {
		return findCookie(request,JWT_COOKIE);
	}

	static Cookie findIdToken(HttpServletRequest request) {
		return findCookie(request,ID_COOKIE);
	}
	
	private static Cookie findCookie(HttpServletRequest request, String name) {
		Cookie[] cookies = request.getCookies();
		// Cookies is null, if request sends no cookie information
		if(cookies == null) {
			return null;
		}
		for(Cookie cookie:cookies) {
			if(cookie.getName().equals(name)) {
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
	private LoginConfiguration loginConfig;
	
	@Inject
	private UserContextProvider userContext;
	
	@Override
	public CredentialValidationResult validateAccessToken(HttpServletRequest request, HttpServletResponse response) {
		if(!loginConfig.isOidcEnabled()) {
			return NOT_VALIDATED_RESULT;
		}
		
		// Validate access token
		Cookie jwsCookie = findAccessToken(request);
		if(jwsCookie == null) {
			return NOT_VALIDATED_RESULT;
		}
		
		Cookie idCookie = findIdToken(request);

		// Parse access token.
		Claims claims = getAccessTokenClaims(response, 
										     jwsCookie, 
										     idCookie);
		
		if(claims == null) {
			// User is not authenticated
			return INVALID_RESULT;
		}
		
		UserId userId =  userId(claims.getSubject());
		Set<String> scopes = stream(claims.get("scope",String.class)
									.split("\\s+"))
							 .collect(toSet()); 
		UserName userName = userName(claims.get("preferred_username",String.class));
		String name = claims.get("name",String.class);
		
		userContext.setUserId(userId);
		userContext.setUserName(userName);
		userContext.setScopes(scopes);
		userContext.setName(name);
		userContext.seal();
		
		return new CredentialValidationResult(userContext.getUserName().toString(),
											  emptySet());
	}

	private Claims getAccessTokenClaims(HttpServletResponse response, Cookie jwsCookie, Cookie idCookie) {
		
		try {
			return oidcConfig
				   .parse(jwsCookie.getValue())
				   .getBody();
		} catch (ExpiredJwtException e) {
			return refreshTokensAndCookies(response, jwsCookie, idCookie, e.getClaims());
		} 
	}
	
	private Claims refreshTokensAndCookies(HttpServletResponse response, Cookie jwsCookie, Cookie idCookie, Claims expiredAccessToken){

		String sub = expiredAccessToken.getSubject();
		String refreshToken = refreshTokens.getRefreshToken(sub);
		if(refreshToken == null) {
			LOG.fine(()->format("Cannot refresh access token for subject %s because no refresh token is present",sub));
			return null; 
		}
		try {
			Oauth2AccessToken oauth2 = client.refreshAccessToken(refreshToken);
			if(expiredAccessToken.getExpiration() != null && expiredAccessToken.getExpiration().before(new Date(currentTimeMillis()-SECONDS.toMillis(oauth2.getRefreshExpiresIn())))){
				LOG.fine(()->format("Cannot refresh access token for subject %s because it has expired too long ago",sub));
				return null;
			}
			
			// Store new refresh token
			refreshTokens.storeRefreshToken(sub, oauth2.getRefreshToken());
			idCookie.setValue(oauth2.getIdToken());
			idCookie.setHttpOnly(true);
			idCookie.setMaxAge(oauth2.getRefreshExpiresIn());
			response.addCookie(idCookie);
			jwsCookie.setValue(oauth2.getAccessToken());
			jwsCookie.setHttpOnly(true);
			jwsCookie.setMaxAge(oauth2.getRefreshExpiresIn());
			response.addCookie(jwsCookie);
			LOG.fine(() -> format("Refreshed access token for user %s.",sub));
			return oidcConfig.parse(oauth2.getAccessToken()).getBody();
		} catch (AccessDeniedException e) {
			LOG.fine(()->format("Authorization service rejected to refresh the access token for subject %s.",sub));
			return null;
		}
		
	}
	 
	
	@Override
	public void invalidateAccessToken(HttpServletRequest request, 
									  HttpServletResponse response) {
		
		if(!loginConfig.isOidcEnabled()) {
			return;
		}
		// Delete access token cookie
		Cookie cookie = new Cookie(JWT_COOKIE,"");
		cookie.setHttpOnly(true);
		cookie.setSecure(request.isSecure());
		cookie.setPath("/");
		cookie.setMaxAge(0);
		response.addCookie(cookie);	
		// Delete ID token cookie
		cookie = new Cookie(ID_COOKIE,"");
		cookie.setHttpOnly(true);
		cookie.setSecure(request.isSecure());
		cookie.setPath("/");
		cookie.setMaxAge(0);
		response.addCookie(cookie);	
		
		try{
			String referer = request.getHeader("Referer");
			response.sendRedirect(oidcConfig.getEndSessionEndpoint()+"?redirect_uri="+encode(referer, "UTF-8"));
		} catch (Exception e) {
			LOG.log(FINE,
					e.getMessage(),
					format("Failed to redirect to end session endpoint: %s",e.getMessage()));
		} 
	}
	
}
