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
package io.leitstand.security.sso.oidc.auth;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.security.auth.UserName.userName;
import static java.lang.String.format;
import static java.lang.System.currentTimeMillis;
import static java.net.URLEncoder.encode;
import static java.util.Collections.emptySet;
import static java.util.logging.Level.FINE;
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

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.http.AccessTokenManager;
import io.leitstand.security.auth.http.UserContextProvider;
import io.leitstand.security.auth.jwt.Claims;
import io.leitstand.security.oauth2.Oauth2AccessToken;
import io.leitstand.security.sso.oidc.config.OidcConfig;
import io.leitstand.security.sso.oidc.oauth2.RefreshTokenStore;
import io.leitstand.security.sso.oidc.service.OidcService;

/**
 * Scans the HTTP request for a Leitstand access token cookie and validates the discovered access token.
 * <p>
 * The cookie names default to <code>LEISTAND_ACCESS</code> and <code>LEISTAND_ID</code> and can be changed by
 * setting the <code>LEISTAND_ACCESS_TOKEN_COOKIE_NAME</code> and <code>LEISTAND_ID_TOKEN_COOKIE_NAME</code> environment properties.
 * <p>
 * The cookie manager attempts to refresh expired access tokens, which fails if the user's refresh token is also expired.
 * Access is declined if the access token is invalid or if the token is expired and cannot be refreshed.
 * <p>
 * The cookie manager also supports invalidating an access token. The browser gets instructed to drop all Leitstand cookies 
 * and gets then redirected to OpenID/Connect end-session endpoint to terminate the user's session in the OpenID/Connect server.
 */
@Dependent
public class CookieManager implements AccessTokenManager{

	private static final Logger LOG = Logger.getLogger(CookieManager.class.getName());
	
	private static final String JWT_COOKIE = getSystemProperty("LEITSTAND_ACCESS_TOKEN_COOKIE_NAME","LEITSTAND_ACCESS");
	private static final String ID_COOKIE  = getSystemProperty("LEITSTAND_ID_TOKEN_COOKIE_NAME","LEITSTAND_ID");
	

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
	
	
	private OidcService client;
	
	private RefreshTokenStore refreshTokens;
	
	private OidcConfig oidcConfig;
	
	private UserContextProvider userContext;
	
	
	protected CookieManager() {
		// CDI
	}
	
	@Inject
	protected CookieManager(OidcService client, 
							RefreshTokenStore refreshTokens, 
							OidcConfig oidcConfig, 
							UserContextProvider userContext) {
		this.client = client;
		this.refreshTokens = refreshTokens;
		this.oidcConfig = oidcConfig;
		this.userContext = userContext;
		
	}
	
	
	/**
	 * Scans the HTTP request for a leitstand access token cookie and validate the discovered access token. Creates a sealed user context if
	 * the token is valid.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @return <code>NOT_VALIDATED_RESULT</code> if OpenID/Connect is disabled or not access token cookie is available, 
	 * <code>INVALID_RESULT</code> if the access token is invalid or expired and a <code>VALID</code> result if the access token is valid.
	 */
	@Override
	public CredentialValidationResult validateAccessToken(HttpServletRequest request, HttpServletResponse response) {
        if(oidcConfig == null) {
            // OpenID/Connect is not enabled.
			return NOT_VALIDATED_RESULT;
		}
		
		// Validate access token
		Cookie jwtCookie = findAccessToken(request);
		if(jwtCookie == null) {
			return NOT_VALIDATED_RESULT;
		}
		
		Cookie idCookie = findIdToken(request);

		// Parse access token.
		Claims claims = getAccessTokenClaims(response, 
										     jwtCookie, 
										     idCookie);
		
		if(claims == null) {
			// User is not authenticated
			return INVALID_RESULT;
		}
		
		Set<String> scopes = claims.getScopes();
		UserName userName = userName(claims.getClaim("preferred_username"));
		
		userContext.setUserName(userName);
		userContext.setScopes(scopes);
		userContext.seal();
		
		return new CredentialValidationResult(userContext.getUserName().toString(),
											  emptySet());
	}

	private Claims getAccessTokenClaims(HttpServletResponse response, Cookie jwtCookie, Cookie idCookie) {
		
	    Claims claims = oidcConfig.decodeAccessToken(jwtCookie.getValue());
	    if(claims.isExpired()) {
	        return refreshTokensAndCookies(response, jwtCookie, idCookie, claims);
		} 
	    return claims;
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
			// Store new refresh token
			refreshTokens.storeRefreshToken(sub, oauth2.getRefreshToken(), new Date(currentTimeMillis()+1000*oauth2.getRefreshExpiresIn()));
			idCookie.setPath("/");
			idCookie.setValue(oauth2.getIdToken());
			idCookie.setHttpOnly(true);
			idCookie.setMaxAge(oauth2.getRefreshExpiresIn()); // Let cookie expire after the access token!
			response.addCookie(idCookie);
			jwsCookie.setPath("/");
			jwsCookie.setValue(oauth2.getAccessToken());
			jwsCookie.setHttpOnly(true);
			jwsCookie.setMaxAge(oauth2.getRefreshExpiresIn()); // Let cookie expire after the access token! 
			response.addCookie(jwsCookie);
			LOG.fine(() -> format("Refreshed access token for user %s.",sub));
			return oidcConfig.decodeAccessToken(oauth2.getAccessToken());
		} catch (AccessDeniedException e) {
			LOG.fine(()->format("Authorization service rejected to refresh the access token for subject %s.",sub));
			return null;
		}
		
	}
	
	
	/**
	 * Invalidates the Leitstand access token by clearing the Leitstand session cookies and redirecting the user-agent to the end-session endpoint.
	 * Does nothing when OpenID/Connect is disabled.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 */
	@Override
	public void invalidateAccessToken(HttpServletRequest request, 
									  HttpServletResponse response) {
		
		if(oidcConfig == null) {
		    // OpenID/Connect is not enabled.
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
