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

import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.sso.standalone.auth.HttpServletRequestMother.cookieAuthenticationRequest;
import static io.leitstand.security.users.service.UserInfo.newUserInfo;
import static java.lang.Boolean.TRUE;
import static java.lang.System.currentTimeMillis;
import static java.time.Duration.ofMinutes;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.INVALID;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.util.Date;
import java.util.Set;

import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.nimbusds.jwt.JWTClaimsSet;

import io.leitstand.security.auth.http.UserContextProvider;
import io.leitstand.security.auth.jwt.Claims;
import io.leitstand.security.auth.jwt.JwtException;
import io.leitstand.security.auth.user.UserRegistry;
import io.leitstand.security.sso.standalone.config.StandaloneLoginConfig;

@RunWith(MockitoJUnitRunner.class)
public class CookieManagerTest {

	static Set<String> scopes(String... scopes){
		return asSet(scopes);
	}
	
	@Mock
	private UserRegistry users;
	
	@Mock
	private UserContextProvider userContext;
	
	@Mock
	private StandaloneLoginConfig loginConfig;
	
	@InjectMocks
	private CookieManager manager = new CookieManager();
	
	private HttpServletResponse response = mock(HttpServletResponse.class);
	
	@Before
	public void setTokenConfig() {
		when(loginConfig.getTimeToLive()).thenReturn(ofMinutes(60));
		when(loginConfig.getRefreshInterval()).thenReturn(ofMinutes(1));
	}
	
	@Test
	public void not_validated_when_no_cookies_are_present() {
		CredentialValidationResult result = manager.validateAccessToken(mock(HttpServletRequest.class), 
							 											response);
		assertEquals(NOT_VALIDATED_RESULT, result);
		verifyZeroInteractions(users);
	}
	
	@Test
	public void not_validated_when_no_JWT_cookie_is_present() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getCookies()).thenReturn(new Cookie[0]);
		
		CredentialValidationResult result = manager.validateAccessToken(request, 
																		response);
		assertEquals(NOT_VALIDATED_RESULT, result);
		verifyZeroInteractions(users);
	}
	
	@Test
	public void deny_access_when_access_token_is_valid_but_does_not_include_requested_scope() {
		Claims claims = mock(Claims.class);
		when(claims.getScopes()).thenReturn(asSet("a,b"));
		when(claims.getClaim("preferred_username")).thenReturn("unittest");
		
		when(loginConfig.decodeAccessToken("TOKEN")).thenReturn(claims);
		
		CredentialValidationResult result = manager.validateAccessToken(cookieAuthenticationRequest(), 
																 		response);
		assertEquals(INVALID, result.getStatus());
		assertTrue(result.getCallerGroups().isEmpty());
		verifyZeroInteractions(users);
	}
	
	
	@Test
	public void renew_cookie_when_valid_cookie_is_about_to_expire() throws Exception{
        Claims claims = mock(Claims.class);
        when(claims.getScopes()).thenReturn(asSet("a,b"));
		when(claims.getSubject()).thenReturn("unittest");
		when(claims.getExpiresAt()).thenReturn(new Date(currentTimeMillis()+10000));
		when(loginConfig.decodeAccessToken(anyString())).thenReturn(claims);
		when(users.getUserInfo(userName("unittest"))).thenReturn(newUserInfo()
																 .withUserName(userName("unittest"))
																 .build());
	
		HttpServletRequest request = cookieAuthenticationRequest();

		CredentialValidationResult result = manager.validateAccessToken(request, 
													 			 		response);
		assertEquals(VALID, result.getStatus());
	}
	
	
	@Test
	public void reject_access_when_cookie_is_outdated() throws Exception{
        Claims claims = mock(Claims.class);
        when(claims.getScopes()).thenReturn(asSet("a,b"));
		when(claims.getClaim("preferred_username")).thenReturn("unittest");
		when(claims.isExpired()).thenReturn(TRUE);
		
		when(loginConfig.decodeAccessToken("TOKEN")).thenReturn(claims);

		CredentialValidationResult result = manager.validateAccessToken(cookieAuthenticationRequest(), 
							 			 		 				 		response);
		assertEquals(INVALID_RESULT, result);	
		verifyZeroInteractions(users);
	}
	
	@Test
	public void reject_access_when_access_token_is_invalid() throws Exception{
		// Throw an exception to indicate that the token is invalid.
		// All exceptions are read as "token invalid".
		when(loginConfig.decodeAccessToken("TOKEN")).thenThrow(new JwtException("unittest"));
		
		CredentialValidationResult result = manager.validateAccessToken(cookieAuthenticationRequest(), 
																		response);
		assertEquals(INVALID_RESULT, result);
		verifyZeroInteractions(users);
	}
	

	@Test
	public void do_nothing_when_standalone_is_disabled() {
	    // Create a manager without config to make sure that the cookie manager does not authenticate the request.
	    manager = new CookieManager();
	    
		assertEquals(NOT_VALIDATED_RESULT, manager.validateAccessToken(cookieAuthenticationRequest(), response));
		assertFalse(manager.issueAccessToken(cookieAuthenticationRequest(), response, userName("unittest")));
	}
	
}
