/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;

import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.auth.http.Authorization.HTTP_AUTHORIZATION_HEADER;
import static java.util.Base64.getEncoder;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.Mockito.mock;
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


@RunWith(MockitoJUnitRunner.class)
public class BasicAuthManagerTest {

	@Mock
	private IdentityStore is;
	
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
	public void decode_and_verify_credentials() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Basic "+getEncoder().encodeToString(toUtf8Bytes("user:password")));
		
		ArgumentCaptor<UsernamePasswordCredential> credentialCaptor = forClass(UsernamePasswordCredential.class);
		
		when(is.validate(credentialCaptor.capture())).thenReturn(INVALID_RESULT);
		
		manager.validateAccessToken(request, 
					  			  	mock(HttpServletResponse.class));
		UsernamePasswordCredential credentials = credentialCaptor.getValue();
		assertEquals("user", credentials.getCaller());
		assertEquals("password",credentials.getPasswordAsString());
	}
}
