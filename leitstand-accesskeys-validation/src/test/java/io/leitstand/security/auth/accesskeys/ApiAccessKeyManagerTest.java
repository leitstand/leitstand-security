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
package io.leitstand.security.auth.accesskeys;


import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.accesskeys.ReasonCode.AKY0100E_INVALID_ACCESSKEY;
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

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.accesskey.ApiAccessKeyDecoder;
import io.leitstand.security.auth.http.Authorization;
import io.leitstand.security.auth.standalone.StandaloneLoginConfig;

@RunWith(MockitoJUnitRunner.class)
public class ApiAccessKeyManagerTest {

	@Mock
	private ApiAccessKeyDecoder keyDecoder;
	
	@Mock
	private AccessKeyValidator authenticator;
	
	@Mock
	private StandaloneLoginConfig loginConfig;
	
	@InjectMocks
	private ApiAccessKeyManager manager = new ApiAccessKeyManager();
	
	@Test
	public void do_nothing_if_no_authorization_header_is_present() {
		when(loginConfig.isApiAccessKeysEnabled()).thenReturn(true);
		CredentialValidationResult result = manager.validateAccessToken(mock(HttpServletRequest.class), 
																		mock(HttpServletResponse.class));

		assertEquals(NOT_VALIDATED_RESULT, result);
		verifyZeroInteractions(authenticator,
							   keyDecoder);
	}
	
	@Test
	public void do_nothing_if_authentication_is_not_bearer() {
		when(loginConfig.isApiAccessKeysEnabled()).thenReturn(true);

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
		when(loginConfig.isApiAccessKeysEnabled()).thenReturn(true);

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
		when(loginConfig.isApiAccessKeysEnabled()).thenReturn(true);

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Bearer ACCESSKEY");
		when(keyDecoder.decode("ACCESSKEY")).thenThrow(new AccessDeniedException(AKY0100E_INVALID_ACCESSKEY));
		
		CredentialValidationResult result = manager.validateAccessToken(request,
																		mock(HttpServletResponse.class)); 
		
		assertEquals(INVALID_RESULT,result);
		verifyZeroInteractions(authenticator);
	}
	
	
	@Test
	public void reject_access_for_accesskey_with_insufficient_privileges() {
		when(loginConfig.isApiAccessKeysEnabled()).thenReturn(true);

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Bearer ACCESSKEY");
		ApiAccessKey token = mock(ApiAccessKey.class);
		when(token.getUserName()).thenReturn(userName("unittest"));
		when(keyDecoder.decode("ACCESSKEY")).thenReturn(token);
		when(authenticator.isValid(request, token)).thenReturn(FALSE);
		
		CredentialValidationResult result = manager.validateAccessToken(request,
																		mock(HttpServletResponse.class));
		
		assertEquals(INVALID_RESULT,result);
	}
	
	@Test
	public void grant_access_for_accesskey_with_sufficient_privileges() {
		when(loginConfig.isApiAccessKeysEnabled()).thenReturn(true);

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Bearer ACCESSKEY");

		ApiAccessKey token = mock(ApiAccessKey.class);
		when(token.getUserName()).thenReturn(userName("unittest"));
		when(keyDecoder.decode("ACCESSKEY")).thenReturn(token);
		when(authenticator.isValid(request, token)).thenReturn(TRUE);
		
		CredentialValidationResult result = manager.validateAccessToken(request,
																		mock(HttpServletResponse.class));
		
		assertEquals(VALID,result.getStatus());
		assertEquals("unittest", result.getCallerPrincipal().getName());
	}
	
	@Test
	public void do_nothing_when_api_accesskeys_are_disabled() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		CredentialValidationResult result = manager.validateAccessToken(request,
				                                                        mock(HttpServletResponse.class));
		assertEquals(NOT_VALIDATED_RESULT,result);
	}
	
	@Test
	public void do_nothing_when_bearer_token_does_not_match_access_key_format() {
		when(loginConfig.isApiAccessKeysEnabled()).thenReturn(true);

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Bearer ACCESSKEY");
		
		CredentialValidationResult result = manager.validateAccessToken(request,
																		mock(HttpServletResponse.class));
		
		assertEquals(NOT_VALIDATED_RESULT,result);
	}
}
