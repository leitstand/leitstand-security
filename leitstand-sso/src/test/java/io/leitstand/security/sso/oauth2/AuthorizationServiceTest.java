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
package io.leitstand.security.sso.oauth2;

import static io.leitstand.security.sso.oauth2.SecurityContextMother.authenticatedAs;
import static io.leitstand.security.sso.oauth2.SecurityContextMother.unauthenticated;
import static javax.ws.rs.core.Response.Status.TEMPORARY_REDIRECT;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.leitstand.commons.messages.Messages;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.accesskey.ApiAccessKeyEncoder;
import io.leitstand.security.auth.standalone.StandaloneLoginConfig;
import io.leitstand.security.auth.user.UserInfo;
import io.leitstand.security.auth.user.UserRegistry;

@RunWith(MockitoJUnitRunner.class)
public class AuthorizationServiceTest {

	@Mock
	private Messages messages;
	
	@Mock
	private UserRegistry users;
	
	@Mock
	private ApiAccessKeyEncoder encoder;
	
	@Mock
	private StandaloneLoginConfig config;
	
	
	@InjectMocks
	private AuthorizationService service = new AuthorizationService();


	
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
		when(config.signJwt(any(JwtBuilder.class))).thenReturn("AUTHCODE");
		Response response = service.authorize(authenticatedAs("junit"), "junit", "code", "junit", "http://localhost:9080/junit",null);
		assertEquals(TEMPORARY_REDIRECT.getStatusCode() , response.getStatus());
		assertEquals("http://localhost:9080/junit?code=AUTHCODE",response.getHeaderString("Location"));
	}
	
	@Test
	public void preserve_state_if_response_type_is_code_and_caller_is_authenticated() throws IOException{
		when(config.signJwt(any(JwtBuilder.class))).thenReturn("AUTHCODE");
		
		Response response = service.authorize(authenticatedAs("junit"), "junit", "code", "client", "http://localhost:9080/junit","1234");

		assertEquals(TEMPORARY_REDIRECT.getStatusCode() , response.getStatus());
		assertEquals("http://localhost:9080/junit?code=AUTHCODE&state=1234",response.getHeaderString("Location"));
		
	}
	
	@Test
	public void reject_access_token_request_when_client_id_mismatches() {
		Jws<Claims> jws = mock(Jws.class);
		Claims claims = mock(Claims.class);
		when(jws.getBody()).thenReturn(claims);
		when(claims.getAudience()).thenReturn("foo");
		
		when(config.decodeJws("AUTHCODE")).thenReturn(jws);
		
		Response response = service.getAccessToken(authenticatedAs("junit"),null,"AUTHCODE");
		assertEquals(Status.FORBIDDEN.getStatusCode(),response.getStatus());
	}
	
	@Test
	public void issue_access_token_request_when_client_id_matches() {
		UserInfo user = mock(UserInfo.class);
		when(user.getUserName()).thenReturn(UserName.valueOf("client"));
		when(users.getUserInfo(UserName.valueOf("client"))).thenReturn(user);

		Jws<Claims> jws = mock(Jws.class);
		Claims claims = mock(Claims.class);
		when(jws.getBody()).thenReturn(claims);
		when(claims.getAudience()).thenReturn("junit");
		when(claims.getSubject()).thenReturn("client");
		
		when(config.decodeJws("AUTHCODE")).thenReturn(jws);

		
		Response response = service.getAccessToken(authenticatedAs("junit"),null,"AUTHCODE");
		assertEquals(Status.OK.getStatusCode(),response.getStatus());
	}
}
