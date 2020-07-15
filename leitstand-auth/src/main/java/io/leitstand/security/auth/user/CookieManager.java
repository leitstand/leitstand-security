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
package io.leitstand.security.auth.user;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.commons.jsonb.IsoDateAdapter.isoDateFormat;
import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.security.auth.UserName.userName;
import static java.lang.String.format;
import static java.lang.System.currentTimeMillis;
import static java.util.Collections.emptySet;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINER;
import static java.util.logging.Logger.getLogger;
import static java.util.stream.Collectors.joining;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

import java.time.Duration;
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
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.http.AccessTokenManager;
import io.leitstand.security.auth.http.UserContextProvider;
import io.leitstand.security.auth.standalone.StandaloneLoginConfig;


@Dependent
public class CookieManager implements AccessTokenManager{
	
	private static final String JWS_COOKIE = getSystemProperty("LEITSTAND_JWS_COOKIE_NAME","LEITSTAND_ACCESS");
	private static final Logger LOG = getLogger(CookieManager.class.getName());
	
	static Cookie findAccessToken(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		// Cookies is null, if request sends no cookie information
		if(cookies == null) {
			return null;
		}
		for(Cookie cookie:cookies) {
			if(cookie.getName().equals(JWS_COOKIE)) {
				return cookie;
			}
		}
		return null;
	}
	
	@Inject
	private UserRegistry userRegistry;
	
	@Inject
	private UserContextProvider userContext;
	
	@Inject
	private StandaloneLoginConfig config;
	
	@Override
	public boolean issueAccessToken(HttpServletRequest request,
									HttpServletResponse response,
									UserName userName) {
		if(!config.isJwsEnabled()) {
			return false;
		}
		UserInfo user = userRegistry.getUserInfo(userName);
		Date expiryDate = computeExpiryDate(user);
		String jws = createJws(user, expiryDate);
		
		writeCookie(request, 
					response, 
					jws,
					(int)(expiryDate.getTime() - currentTimeMillis())/1000);
		
		LOG.fine(() -> format("User %s login succeeded!",userName));
		return true;
	}

	private String createJws(UserInfo userInfo, Date expiryDate) {
		String jws = config.signJwt(Jwts.builder()
										.setIssuedAt(new Date())
										.setExpiration(expiryDate)
										.setSubject(userInfo.getUserName().toString())
										.claim("scope",userInfo.getScopes().stream().collect(joining(" "))));
		return jws;
	}

	private Date computeExpiryDate(UserInfo user){
		if(user.getAccessTokenTtl() != null && user.getAccessTokenTtlUnit() != null) {
			return new Date(currentTimeMillis()+user.getAccessTokenTtlUnit().toMillis(user.getAccessTokenTtl()));
		}
		return new Date(currentTimeMillis()+config.getTimeToLive().toMillis());
	}
	
	
	private void writeCookie(HttpServletRequest request, 
							 HttpServletResponse response, 
							 String jws,
							 int maxAgeSeconds) {
		
		Cookie cookie = findAccessToken(request);
		if(cookie == null) {
			cookie = new Cookie(JWS_COOKIE, jws);
		} else {
			cookie.setValue(jws);
		} 
		cookie.setMaxAge(maxAgeSeconds);
		cookie.setHttpOnly(true);
		cookie.setSecure(request.isSecure());
		cookie.setPath("/");
		cookie.setMaxAge(maxAgeSeconds);
		response.addCookie(cookie);
	}


	@Override
	public void invalidateAccessToken(HttpServletRequest request, 
									  HttpServletResponse response) {
		if(!config.isJwsEnabled()) {
			return;
		}
		Cookie cookie = new Cookie(JWS_COOKIE,"");
		cookie.setHttpOnly(true);
		cookie.setSecure(request.isSecure());
		cookie.setPath("/");
		cookie.setMaxAge(0);
		response.addCookie(cookie);			
		try {
			response.sendRedirect("/ui/login/login.html");
		} catch (Exception e) {
			LOG.log(FINE,
					e.getMessage(),
					format("Failed to redirect to end session endpoint: %s",e.getMessage()));
		}
	}


	@Override
	public CredentialValidationResult validateAccessToken(HttpServletRequest request, 
												   		  HttpServletResponse response) {
		if(!config.isJwsEnabled()) {
			return NOT_VALIDATED_RESULT;
		}
		
		Cookie jwsCookie = findAccessToken(request);		
		if(jwsCookie == null) {
			LOG.fine(() -> format("No %s cookie available.",JWS_COOKIE));
			return NOT_VALIDATED_RESULT;
		}
		try {
			Jws<Claims> jws = config.decodeJws(jwsCookie.getValue());

			UserName 	userName	  = userName(jws.getBody().getSubject());
			Set<String> grantedScopes = readScopes(jws);
			Date 		dateCreated   = jws.getBody().getIssuedAt();
			Date 		dateExpires   = jws.getBody().getExpiration();
			
			if(isExpired(jws)) {
				LOG.fine(() -> format("Token for user %s created at %s expired at %s.",
									  userName,
									  isoDateFormat(dateCreated),
									  isoDateFormat(dateExpires)));
				invalidateAccessToken(request, response);
				return INVALID_RESULT;
			}
			
			
			if(refreshToken(jws)) {
				LOG.fine(() -> format("Refreshing token for user %s created at %s.",
									  userName,
									  isoDateFormat(dateCreated)));
				
				// Fetch user again to apply recent roles to access token.
				// Throws an EntityNotFoundException, if the user does not exist!
				UserInfo user = userRegistry.getUserInfo(userName);
				if(user == null) {
					return INVALID_RESULT;
				}
				Date expiry = computeExpiryDate(user);
				
				writeCookie(request, 
							response, 
							createJws(user,expiry),
							(int)(expiry.getTime() - currentTimeMillis())/1000);
				
			}
			
			userContext.setUserName(userName(jws.getBody().getSubject()));
			userContext.setScopes(grantedScopes);
			userContext.seal();
			
			return new CredentialValidationResult(userName.toString(),
												  emptySet());

			
			
		} catch (Exception e) {
			LOG.log(FINER,e.getMessage(),e);
			return INVALID_RESULT;
		}		
	}

	private boolean isExpired(Jws<Claims> jws) {
		return currentTimeMillis() > jws.getBody().getExpiration().getTime();
	}
	
	private Set<String> readScopes(Jws<Claims> jws) {
		return asSet(jws.getBody().get("scope",String.class).split("\\s"));
	}
	
	private boolean refreshToken(Jws<Claims> jws) {
		Duration refreshInterval = config.getRefreshInterval();
		Date expiry = jws.getBody().getExpiration();
		return expiry.getTime() < currentTimeMillis() + refreshInterval.toMillis();
	}
	
	
	
}
