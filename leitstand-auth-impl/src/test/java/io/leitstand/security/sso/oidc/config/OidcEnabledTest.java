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
package io.leitstand.security.sso.oidc.config;

import static io.leitstand.security.auth.UserName.userName;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

import java.util.Collection;

import javax.security.enterprise.credential.Password;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.jwt.JwtDecoder;

@RunWith(Parameterized.class)
public class OidcEnabledTest {

	private static final String AUTHORIZATION_ENDPOINT = "http://localhost/authorize";
	private static final String TOKEN_ENDPOINT = "http://localhost/token";
	private static final String USER_ENDPOINT = "http://localhost/userinfo";
	private static final String ENDSESSION_ENDPOINT = "http://localhost/endsession";
	private static final Password CLIENT_SECRET = new Password("secret");
	private static final UserName CLIENT_ID = userName("id");
	private static final JwtDecoder  DECODER = mock(JwtDecoder.class);
	
	
	@Parameters
	public static Collection<Object[]> getParameters(){

		return asList(new Object[][] { 
				{ AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, USER_ENDPOINT, ENDSESSION_ENDPOINT, CLIENT_ID, CLIENT_SECRET, DECODER, true  },
				{ AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, USER_ENDPOINT, ENDSESSION_ENDPOINT, CLIENT_ID, CLIENT_SECRET, null,    false },
				{ AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, USER_ENDPOINT, ENDSESSION_ENDPOINT, CLIENT_ID, null,			DECODER, false },
				{ AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, USER_ENDPOINT, ENDSESSION_ENDPOINT, null, 	 CLIENT_SECRET, DECODER, false },
				{ AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, USER_ENDPOINT, null, 				  CLIENT_ID, CLIENT_SECRET, DECODER, false },
				{ AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, USER_ENDPOINT, "",				  CLIENT_ID, CLIENT_SECRET, DECODER, false },
				{ AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, null,          ENDSESSION_ENDPOINT, CLIENT_ID, CLIENT_SECRET, DECODER, false },
				{ AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, "",            ENDSESSION_ENDPOINT, CLIENT_ID, CLIENT_SECRET, DECODER, false },
				{ AUTHORIZATION_ENDPOINT, null,           USER_ENDPOINT, ENDSESSION_ENDPOINT, CLIENT_ID, CLIENT_SECRET, DECODER, false },
				{ AUTHORIZATION_ENDPOINT, "",             USER_ENDPOINT, ENDSESSION_ENDPOINT, CLIENT_ID, CLIENT_SECRET, DECODER, false },
				{ null,                   TOKEN_ENDPOINT, USER_ENDPOINT, ENDSESSION_ENDPOINT, CLIENT_ID, CLIENT_SECRET, DECODER, false },
				{ "",                     TOKEN_ENDPOINT, USER_ENDPOINT, ENDSESSION_ENDPOINT, CLIENT_ID, CLIENT_SECRET, DECODER, false }});

	}
	
	private String authorizationEndpoint;
	private String tokenEndpoint;
	private String userInfoEndpoint;
	private String endSessionEndpoint;
	private UserName clientId;
	private Password clientSecret;
	private boolean openIdEnabledState;
	private JwtDecoder decoder;
	
	private OidcConfigProvider provider;
	
	public OidcEnabledTest(String authorizationEndpoint, 
						   String tokenEndpoint, 
						   String userInfoEndpoint, 
						   String endSessionEndpoint, 
						   UserName clientId, 
						   Password clientSecret, 
						   JwtDecoder decoder, 
						   boolean state) {
		this.provider = new OidcConfigProvider();
		this.authorizationEndpoint = authorizationEndpoint;
		this.tokenEndpoint = tokenEndpoint;
		this.userInfoEndpoint = userInfoEndpoint;
		this.endSessionEndpoint = endSessionEndpoint;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.decoder = decoder;
		this.openIdEnabledState = state;
	}

	@Test
	public void correct_openid_enabled_state() {
		assertThat(openIdEnabledState, is(provider.isOpenIdEnabled(authorizationEndpoint, 
																   tokenEndpoint, 
																   userInfoEndpoint, 
																   endSessionEndpoint, 
																   clientId, 
																   clientSecret, 
																   decoder)));
	}
	
}
