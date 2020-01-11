/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.oauth2;

import static io.leitstand.security.sso.oauth2.AuthorizationCode.newAuthorizationCode;
import static io.leitstand.security.sso.oauth2.SecurityContextMother.authenticatedAs;
import static io.leitstand.security.sso.oauth2.SecurityContextMother.unauthenticated;
import static javax.ws.rs.core.Response.Status.TEMPORARY_REDIRECT;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import io.leitstand.commons.messages.Messages;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.jwt.JsonWebTokenDecoder;
import io.leitstand.security.auth.jwt.JsonWebTokenEncoder;
import io.leitstand.security.auth.user.UserInfo;
import io.leitstand.security.auth.user.UserRegistry;

public class AuthorizationServiceTest {

	private AuthorizationService service;
	private JsonWebTokenEncoder encoder;
	private JsonWebTokenDecoder decoder;
	private Messages messages;
	private UserRegistry users;
	
	@Before
	public void setupUnitUnderTest() {
		encoder = mock(JsonWebTokenEncoder.class);
		when(encoder.encode(Mockito.any())).thenReturn("AUTHCODE");
		decoder = mock(JsonWebTokenDecoder.class);
		messages = mock(Messages.class);
		users = mock(UserRegistry.class);
		service = new AuthorizationService(encoder,
										   decoder,
										   users,
										   messages);
	}
	
	@Test
	public void send_error_if_non_code_response_was_requested() throws IOException {
		Response response = service.authorize(authenticatedAs("junit"), "junit", "foo", "junit", "http://localhost:9080/junit", null);
		assertEquals(TEMPORARY_REDIRECT.getStatusCode() , response.getStatus());
		assertEquals("http://localhost:9080/junit?error=unsupported_response_type",response.getHeaderString("Location"));
	}
	
	@Test
	public void send_error_if_request_is_unauthenticated() throws IOException {
		Response response = service.authorize(unauthenticated(), "junit", "code", "junit", "http://localhost:9080/junit", null);
		assertEquals(TEMPORARY_REDIRECT.getStatusCode() , response.getStatus());
		assertEquals("http://localhost:9080/junit?error=unauthenticated",response.getHeaderString("Location"));
	}
	
	@Test
	public void preserve_state_for_unauthenticated_requests() throws IOException {
		Response response = service.authorize(unauthenticated(), "junit", "code", "junit", "http://localhost:9080/junit", "1234");
		assertEquals(TEMPORARY_REDIRECT.getStatusCode() , response.getStatus());
		assertEquals("http://localhost:9080/junit?error=unauthenticated&state=1234",response.getHeaderString("Location"));
	}
	
	@Test
	public void preserve_state_for_non_code_requests() throws IOException{
		Response response = service.authorize(authenticatedAs("junit"), "junit", "foo", "junit", "http://localhost:9080/junit", "1234");
		assertEquals(TEMPORARY_REDIRECT.getStatusCode() , response.getStatus());
		assertEquals("http://localhost:9080/junit?error=unsupported_response_type&state=1234",response.getHeaderString("Location"));

	}
	
	@Test
	public void create_redirect_if_response_type_is_code_and_caller_is_authenticated() throws IOException {
		Response response = service.authorize(authenticatedAs("junit"), "junit", "code", "junit", "http://localhost:9080/junit",null);
		assertEquals(TEMPORARY_REDIRECT.getStatusCode() , response.getStatus());
		assertEquals("http://localhost:9080/junit?code=AUTHCODE",response.getHeaderString("Location"));
	}
	
	@Test
	public void preserve_state_if_response_type_is_code_and_caller_is_authenticated() throws IOException{
		Response response = service.authorize(authenticatedAs("junit"), "junit", "code", "junit", "http://localhost:9080/junit","1234");
		assertEquals(TEMPORARY_REDIRECT.getStatusCode() , response.getStatus());
		assertEquals("http://localhost:9080/junit?code=AUTHCODE&state=1234",response.getHeaderString("Location"));
	}
	
	@Test
	public void reject_access_token_request_when_client_id_mismatches() {
		AuthorizationCode token = newAuthorizationCode()
								  .withClientId("mismatch")
								  .build();
		
		when(decoder.decode(AuthorizationCode.class, AuthorizationCode.Payload.class, "AUTHCODE")).thenReturn(token);
		Response response = service.getAccessToken(authenticatedAs("junit"),null,"AUTHCODE");
		assertEquals(Status.FORBIDDEN.getStatusCode(),response.getStatus());
	}
	
	@Test
	public void issue_access_token_request_when_client_id_matches() {
		UserInfo user = mock(UserInfo.class);
		when(user.getUserName()).thenReturn(UserName.valueOf("client"));
		when(users.getUserInfo(UserName.valueOf("client"))).thenReturn(user);

		AuthorizationCode token = newAuthorizationCode()
				  				  .withClientId("junit")
				  				  .withUserName(UserName.valueOf("client"))
				  				  .build();
		when(decoder.decode(AuthorizationCode.class, AuthorizationCode.Payload.class, "AUTHCODE")).thenReturn(token);
		Response response = service.getAccessToken(authenticatedAs("junit"),null,"AUTHCODE");
		assertEquals(Status.OK.getStatusCode(),response.getStatus());
	}
}
