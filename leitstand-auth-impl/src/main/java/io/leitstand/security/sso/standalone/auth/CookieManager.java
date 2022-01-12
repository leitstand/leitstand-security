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
package io.leitstand.security.sso.standalone.auth;

import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.commons.jsonb.IsoDateAdapter.isoDateFormat;
import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.jwt.Claims.newClaims;
import static io.leitstand.security.sso.standalone.config.StandaloneLoginConfig.STANDALONE_LOGIN_KEY_ID;
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

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;

import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.http.AccessTokenManager;
import io.leitstand.security.auth.http.UserContextProvider;
import io.leitstand.security.auth.jwt.Claims;
import io.leitstand.security.auth.user.UserRegistry;
import io.leitstand.security.sso.standalone.config.StandaloneLoginConfig;
import io.leitstand.security.users.service.UserInfo;


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
		if(config == null) {
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
	    
	    Claims claims = newClaims()
	                    .issuedAt(new Date())
	                    .expiresAt(expiryDate)
	                    .subject(userInfo.getUserName().toString())
	                    .scopes(userInfo.getScopes())
	                    .build();
	    
		return config.signAccessToken(claims);
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
		if(config == null) {
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
		if(config == null) {
			return NOT_VALIDATED_RESULT;
		}
		
		Cookie jwsCookie = findAccessToken(request);		
		if(jwsCookie == null) {
			LOG.fine(() -> format("No %s cookie available.",JWS_COOKIE));
			return NOT_VALIDATED_RESULT;
		}
		try {
			Claims claims = config.decodeAccessToken(jwsCookie.getValue());

			UserName 	userName	  = userName(claims.getSubject());
			Set<String> grantedScopes = claims.getScopes();
			Date 		dateCreated   = claims.getIssuedAt();
			
			if (claims.isExpired()) {
			    LOG.finer(() -> format("Token %s is expired",claims.getJwtId()));
			    return INVALID_RESULT;
			}
			
			if(refreshToken(claims)) {
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
			
			userContext.setUserName(userName(claims.getSubject()));
			userContext.setScopes(grantedScopes);
			userContext.seal();
			
			return new CredentialValidationResult(userName.toString(),
												  emptySet());
			
		} catch (Exception e) {
			LOG.log(FINER,"Cannot decode acess token: "+e.getMessage(),e);
			return INVALID_RESULT;
		}		
	}

	private boolean refreshToken(Claims claims) {
		Duration refreshInterval = config.getRefreshInterval();
		Date expiry = claims.getExpiresAt();
		return expiry.getTime() < currentTimeMillis() + refreshInterval.toMillis();
	}
	
}
