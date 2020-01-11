/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;

import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.http.AccessToken.newAccessToken;
import static io.leitstand.security.auth.http.HttpServletRequestMother.cookieAuthenticationRequest;
import static io.leitstand.security.auth.user.UserInfo.newUserInfo;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.time.Duration.ofMinutes;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.security.auth.jwt.JsonWebTokenConfig;
import io.leitstand.security.auth.jwt.JsonWebTokenDecoder;
import io.leitstand.security.auth.jwt.JsonWebTokenEncoder;
import io.leitstand.security.auth.jwt.JsonWebTokenSignatureException;
import io.leitstand.security.auth.user.UserRegistry;

@RunWith(MockitoJUnitRunner.class)
public class CookieManagerTest {

	@Mock
	private UserRegistry users;
	
	@Mock
	private JsonWebTokenEncoder encoder;
	
	@Mock
	private JsonWebTokenDecoder decoder;
	
	@Mock
	private JsonWebTokenConfig config;
	
	@InjectMocks
	private CookieManager manager = new CookieManager();
	
	private HttpServletResponse response = mock(HttpServletResponse.class);
	
	@Before
	public void setTokenConfig() {
		when(config.getTimeToLive()).thenReturn(ofMinutes(60));
		when(config.getRefreshInterval()).thenReturn(ofMinutes(1));
	}
	
	@Test
	public void not_validated_when_no_cookies_are_present() {
		CredentialValidationResult result = manager.validateAccessToken(mock(HttpServletRequest.class), 
							 											response);
		assertEquals(NOT_VALIDATED_RESULT, result);
		verifyZeroInteractions(users,
							   encoder,
							   decoder,
							   config);
	}
	
	@Test
	public void not_validated_when_no_JWT_cookie_is_present() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getCookies()).thenReturn(new Cookie[0]);
		
		CredentialValidationResult result = manager.validateAccessToken(request, 
																		response);
		assertEquals(NOT_VALIDATED_RESULT, result);
		verifyZeroInteractions(users,
				   			   encoder,
				   			   decoder,
				   			   config);
	}
	
	@Test
	public void grant_access_when_access_token_is_valid() {
		AccessToken token = newAccessToken()
							.withUserName(userName("unittest"))
							.withRoles("a","b")
							.build();
		when(decoder.decode(AccessToken.class, AccessToken.Payload.class, "TOKEN")).thenReturn(token);
		CredentialValidationResult result = manager.validateAccessToken(cookieAuthenticationRequest(), 
																 		response);
		assertEquals(VALID, result.getStatus());
		assertEquals("unittest",result.getCallerPrincipal().getName());
		assertTrue(result.getCallerGroups().contains("a"));
		assertTrue(result.getCallerGroups().contains("b"));
		verifyZeroInteractions(users,
							   encoder);
	}
	
	@Test
	public void renew_cookie_when_cookie_is_expired(){
		AccessToken token = spy(newAccessToken()
								.withUserName(userName("unittest"))
								.withRoles("a","b")
								.build());		
		when(token.getUserName()).thenReturn(userName("unittest"));
		when(token.isExpired()).thenReturn(FALSE);
		when(token.isExpiringWithin(config.getRefreshInterval())).thenReturn(TRUE);
		
		when(users.getUserInfo(userName("unittest"))).thenReturn(newUserInfo()
																 .withUserName(userName("unittest"))
																 .build());
		
		ArgumentCaptor<AccessToken> newTokenCaptor = forClass(AccessToken.class);
		
		when(decoder.decode(AccessToken.class, AccessToken.Payload.class, "TOKEN")).thenReturn(token);
		when(encoder.encode(newTokenCaptor.capture())).thenReturn("NEWTOKEN");
		
		
		CredentialValidationResult result = manager.validateAccessToken(cookieAuthenticationRequest(), 
													 			 		response);
		assertEquals(VALID, result.getStatus());
		assertEquals(userName("unittest"),newTokenCaptor.getValue().getUserName());
	}
	
	@Test
	public void do_not_renew_cookie_when_cookie_is_expired_and_user_does_not_exist_anymore(){
		AccessToken token = spy(newAccessToken()
								.withUserName(userName("unittest"))
								.withRoles("a","b")
								.build());		
		when(token.getUserName()).thenReturn(userName("unittest"));
		when(token.isExpired()).thenReturn(TRUE);
		
		when(decoder.decode(AccessToken.class, AccessToken.Payload.class, "TOKEN")).thenReturn(token);

		
		
		CredentialValidationResult result = manager.validateAccessToken(cookieAuthenticationRequest(), 
											 			 		 	    response);
		assertEquals(INVALID_RESULT, result);
		verifyZeroInteractions(encoder);
	}
	
	@Test
	public void reject_access_when_cookie_is_outdated() {
		AccessToken token = spy(newAccessToken()
								.withUserName(userName("unittest"))
								.withRoles("a","b")
								.build());		
		when(token.getUserName()).thenReturn(userName("unittest"));
		when(token.isExpired()).thenReturn(TRUE);

		when(decoder.decode(AccessToken.class, AccessToken.Payload.class, "TOKEN")).thenReturn(token);

		CredentialValidationResult result = manager.validateAccessToken(cookieAuthenticationRequest(), 
							 			 		 				 		response);
		assertEquals(INVALID_RESULT, result);	
		verifyZeroInteractions(users,
   			   				   encoder);
	}
	
	@Test
	public void reject_access_when_access_token_is_invalid() {
		when(decoder.decode(AccessToken.class, AccessToken.Payload.class, "TOKEN")).thenThrow(new JsonWebTokenSignatureException("invalid token"));
		CredentialValidationResult result = manager.validateAccessToken(cookieAuthenticationRequest(), 
																		response);
		assertEquals(INVALID_RESULT, result);
		verifyZeroInteractions(users,
						   	   encoder);
	}
	

	
}
