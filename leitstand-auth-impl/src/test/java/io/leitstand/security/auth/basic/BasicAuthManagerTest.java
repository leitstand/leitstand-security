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
package io.leitstand.security.auth.basic;

import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.http.Authorization.HTTP_AUTHORIZATION_HEADER;
import static io.leitstand.security.users.service.UserInfo.newUserInfo;
import static java.util.Base64.getEncoder;
import static java.util.Collections.emptySet;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.security.auth.http.UserContextProvider;
import io.leitstand.security.auth.user.UserRegistry;
import io.leitstand.security.users.service.UserInfo;


@RunWith(MockitoJUnitRunner.class)
public class BasicAuthManagerTest {

	@Mock
	private IdentityStore is;
	
	@Mock
	private UserRegistry users;
	
	@Mock
	private UserContextProvider userContext;
	
	@Mock
	private BasicAuthConfig config;
	
	@InjectMocks
	private BasicAuthManager manager = new BasicAuthManager();
	
	@Test
	public void do_nothing_if_no_authorization_header_is_set() {
		CredentialValidationResult result = manager.validateAccessToken(mock(HttpServletRequest.class), 
														  				mock(HttpServletResponse.class));
		assertEquals(NOT_VALIDATED_RESULT, result);
	}
	
	@Test
	public void do_nothing_for_non_basic_authentication_request() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Bearer TOKEN");
		CredentialValidationResult result = manager.validateAccessToken(request,
																		mock(HttpServletResponse.class));
		assertEquals(NOT_VALIDATED_RESULT, result);
	}
	
	
	@Test
	public void authenticate_request_with_valid_basic_authentication_header_when_basic_auth_is_enabled() {
		when(config.isBasicAuthEnabled()).thenReturn(true);
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Basic "+getEncoder().encodeToString(toUtf8Bytes("user:password")));
		
		UserInfo user = newUserInfo()
						.withUserName(userName("user"))
						.withScopes("a","b").build();
		when(users.getUserInfo(userName("user"))).thenReturn(user);
		
		ArgumentCaptor<UsernamePasswordCredential> credentialCaptor = forClass(UsernamePasswordCredential.class);
		CredentialValidationResult isResult = new CredentialValidationResult(getClass().getName(), 
				  														     "user",
																		     null,
																		     "uuid",
																		     emptySet());
		when(is.validate(credentialCaptor.capture())).thenReturn(isResult);
		
		CredentialValidationResult result =  manager.validateAccessToken(request, 
																		 mock(HttpServletResponse.class));
		assertEquals(result.getStatus(),VALID);
		UsernamePasswordCredential credentials = credentialCaptor.getValue();
		verify(userContext).setUserName(userName("user"));
		verify(userContext).setScopes(asSet("a","b"));
		verify(userContext).seal();
		assertEquals("user", credentials.getCaller());
		assertEquals("password",credentials.getPasswordAsString());
		
	}
	
	
	@Test
	public void reject_request_with_valid_basic_authentication_header_when_basic_auth_is_enabled() {
		when(config.isBasicAuthEnabled()).thenReturn(true);
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Basic "+getEncoder().encodeToString(toUtf8Bytes("user:password")));
		
		ArgumentCaptor<UsernamePasswordCredential> credentialCaptor = forClass(UsernamePasswordCredential.class);
		when(is.validate(credentialCaptor.capture())).thenReturn(INVALID_RESULT);
		
		CredentialValidationResult result = manager.validateAccessToken(request, 
					  			  										mock(HttpServletResponse.class));
		
		assertEquals(INVALID_RESULT, result);
		verify(userContext).seal();
		verifyNoMoreInteractions(userContext);
	}
	
	@Test
	public void reject_access_when_basic_auth_is_disabled() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Basic "+getEncoder().encodeToString(toUtf8Bytes("user:password")));
				
		
		CredentialValidationResult result = manager.validateAccessToken(request, 
																		mock(HttpServletResponse.class));
		
		assertEquals(INVALID_RESULT, result);
		verify(userContext).seal();
		verifyNoMoreInteractions(userContext);
		
	}
}
