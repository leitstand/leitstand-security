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
package io.leitstand.security.sso.standalone.oauth2;

import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.sso.standalone.oauth2.SecurityContextMother.authenticatedAs;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.commons.messages.Messages;
import io.leitstand.security.auth.accesskeys.ApiAccessKeyEncoder;
import io.leitstand.security.auth.user.UserRegistry;
import io.leitstand.security.users.service.UserInfo;

@RunWith(MockitoJUnitRunner.class)
public class AccessTokenServiceTest {

	@Mock
	private Messages messages;
	
	@Mock
	private UserRegistry users;
	
	@Mock
	private ApiAccessKeyEncoder encoder;
	
	@Mock
	private CodeService codes;
	
	@InjectMocks
	private AccessTokenService service = new AccessTokenService();

	@Test
	public void reject_access_token_request_when_client_id_mismatches() {
	    CodePayload payload = new CodePayload("unittest", "user");
		when(codes.decodeCode("AUTHCODE")).thenReturn(payload);
		Response response = service.getAccessToken(authenticatedAs("other_user"),null,"AUTHCODE");
		assertEquals(Status.FORBIDDEN.getStatusCode(),response.getStatus());
	}
	
	@Test
	public void issue_access_token_request_when_client_id_matches() {
		UserInfo user = mock(UserInfo.class);
		when(user.getUserName()).thenReturn(userName("user"));
		when(users.getUserInfo(userName("user"))).thenReturn(user);

	    CodePayload payload = new CodePayload("unittest", "user");
		when(codes.decodeCode("AUTHCODE")).thenReturn(payload);

		Response response = service.getAccessToken(authenticatedAs("unittest"),null,"AUTHCODE");
		assertEquals(Status.OK.getStatusCode(),response.getStatus());
	}

	
}
