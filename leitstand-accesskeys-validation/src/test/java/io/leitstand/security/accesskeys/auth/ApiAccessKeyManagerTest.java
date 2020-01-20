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
package io.leitstand.security.accesskeys.auth;


import static io.leitstand.security.auth.http.Authorization.HTTP_AUTHORIZATION_HEADER;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.accesskey.ApiAccessKeyDecoder;
import io.leitstand.security.auth.http.Authorization;
import io.leitstand.security.auth.jwt.JsonWebTokenSignatureException;

@RunWith(MockitoJUnitRunner.class)
public class ApiAccessKeyManagerTest {

	@Mock
	private ApiAccessKeyDecoder keyDecoder;
	
	@Mock
	private AccessKeyAuthenticator authenticator;
	
	@InjectMocks
	private ApiAccessKeyManager manager = new ApiAccessKeyManager();
	
	@Test
	public void do_nothing_if_no_authorization_header_is_present() {
		CredentialValidationResult result = manager.validateAccessToken(mock(HttpServletRequest.class), 
																		mock(HttpServletResponse.class));

		assertEquals(NOT_VALIDATED_RESULT, result);
		verifyZeroInteractions(authenticator,
							   keyDecoder);
	}
	
	@Test
	public void do_nothing_if_authentication_is_not_bearer() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(Authorization.HTTP_AUTHORIZATION_HEADER)).thenReturn("Basic CREDENTIALS");
		CredentialValidationResult result = manager.validateAccessToken(request, 
																		mock(HttpServletResponse.class));
		
		assertEquals(NOT_VALIDATED_RESULT,result);
		verifyZeroInteractions(authenticator,
							   keyDecoder);

	}
	
	
	@Test
	public void do_nothing_if_bearer_token_is_JWT_token() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(Authorization.HTTP_AUTHORIZATION_HEADER)).thenReturn("Basic JWT.AUTH.TOKEN");
		CredentialValidationResult result = manager.validateAccessToken(request, 
																		mock(HttpServletResponse.class));
		
		assertEquals(NOT_VALIDATED_RESULT,result);
		verifyZeroInteractions(authenticator,
							   keyDecoder);

	}
	
	@Test
	public void reject_access_for_invalid_accesskey() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Bearer ACCESSKEY");
		when(keyDecoder.decode("ACCESSKEY")).thenThrow(new JsonWebTokenSignatureException("invalid signature"));
		
		CredentialValidationResult result = manager.validateAccessToken(request,
																		mock(HttpServletResponse.class)); 
		
		assertEquals(INVALID_RESULT,result);
		verifyZeroInteractions(authenticator);
	}
	
	
	@Test
	public void reject_access_for_accesskey_with_insufficient_privileges() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Bearer ACCESSKEY");
		ApiAccessKey token = mock(ApiAccessKey.class);
		when(token.getUserName()).thenReturn(UserName.valueOf("unittest"));
		when(keyDecoder.decode("ACCESSKEY")).thenReturn(token);
		when(authenticator.isAllowed(request, token)).thenReturn(FALSE);
		
		CredentialValidationResult result = manager.validateAccessToken(request,
																		mock(HttpServletResponse.class));
		
		assertEquals(INVALID_RESULT,result);
	}
	
	@Test
	public void grant_access_for_accesskey_with_sufficient_privileges() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Bearer ACCESSKEY");

		ApiAccessKey token = mock(ApiAccessKey.class);
		when(token.getUserName()).thenReturn(UserName.valueOf("unittest"));
		when(keyDecoder.decode("ACCESSKEY")).thenReturn(token);
		when(authenticator.isAllowed(request, token)).thenReturn(TRUE);
		
		CredentialValidationResult result = manager.validateAccessToken(request,
																		mock(HttpServletResponse.class));
		
		assertEquals(VALID,result.getStatus());
		assertEquals("unittest", result.getCallerPrincipal().getName());
	}
}
