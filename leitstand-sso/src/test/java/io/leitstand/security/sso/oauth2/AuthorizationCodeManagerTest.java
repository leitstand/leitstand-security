/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.oauth2;

import static io.leitstand.security.auth.http.Authorization.HTTP_AUTHORIZATION_HEADER;
import static io.leitstand.security.sso.oauth2.AuthorizationCode.newAuthorizationCode;
import static java.lang.Boolean.TRUE;
import static java.util.concurrent.TimeUnit.SECONDS;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
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
import io.leitstand.security.auth.jwt.JsonWebTokenDecoder;
import io.leitstand.security.auth.jwt.JsonWebTokenSignatureException;

@RunWith(MockitoJUnitRunner.class)
public class AuthorizationCodeManagerTest {

	@Mock
	private JsonWebTokenDecoder decoder;
	
	@InjectMocks
	private AuthorizationCodeManager manager = new AuthorizationCodeManager();


	@Test
	public void do_nothing_if_no_authorization_header_is_set() {
		CredentialValidationResult result = manager.validateAccessToken(mock(HttpServletRequest.class), 
																		mock(HttpServletResponse.class));
		assertEquals(NOT_VALIDATED_RESULT,result);
		
	}
	
	@Test
	public void do_nothing_if_no_authorization_header_is_no_bearer_token() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Basic CREDENTIALS");
		CredentialValidationResult result = manager.validateAccessToken(request, 
																		mock(HttpServletResponse.class));
		assertEquals(NOT_VALIDATED_RESULT,result);
	}
	
	@Test
	public void do_nothing_if_token_is_no_JWT_token() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Bearer TOKEN");
		CredentialValidationResult result = manager.validateAccessToken(request, 
																		mock(HttpServletResponse.class));
		assertEquals(NOT_VALIDATED_RESULT,result);
	}
	
	@Test
	public void deny_access_for_invalid_token() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Bearer JWT.AUTH.TOKEN");
		when(decoder.decode(AuthorizationCode.class, 
							AuthorizationCode.Payload.class, 
							"JWT.AUTH.TOKEN"))
		.thenThrow(new JsonWebTokenSignatureException("Invalid token signature"));
		
		CredentialValidationResult result = manager.validateAccessToken(request, 
																		mock(HttpServletResponse.class));
		
		assertEquals(INVALID_RESULT,result);
	}
	
	@Test
	public void deny_access_for_expired_token() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Bearer JWT.AUTH.TOKEN");
		AuthorizationCode code = mock(AuthorizationCode.class);
		when(code.isOlderThan(60, SECONDS)).thenReturn(TRUE);
		when(decoder.decode(AuthorizationCode.class, 
							AuthorizationCode.Payload.class, 
							"JWT.AUTH.TOKEN"))
		.thenReturn(code);
		
		CredentialValidationResult result = manager.validateAccessToken(request, 
																		mock(HttpServletResponse.class));
		
		assertEquals(INVALID_RESULT,result);
	}
	
	@Test
	public void grant_access_for_valid_token() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader(HTTP_AUTHORIZATION_HEADER)).thenReturn("Bearer JWT.AUTH.TOKEN");
		when(decoder.decode(AuthorizationCode.class, 
							AuthorizationCode.Payload.class, 
							"JWT.AUTH.TOKEN"))
		.thenReturn(newAuthorizationCode()
					.withUserName(UserName.valueOf("unittest"))
					.build());
		
		CredentialValidationResult result = manager.validateAccessToken(request, 
																		mock(HttpServletResponse.class));
		
		assertEquals("unittest",result.getCallerPrincipal().getName());
	}

}
