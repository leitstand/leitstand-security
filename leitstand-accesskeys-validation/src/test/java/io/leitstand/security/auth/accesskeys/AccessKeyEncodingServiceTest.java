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

import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.security.auth.accesskey.AccessKeyId.randomAccessKeyId;
import static io.leitstand.security.auth.accesskey.ApiAccessKey.newApiAccessKey;
import static io.leitstand.security.mac.MessageAuthenticationCodes.hmacSha256;
import static java.util.Base64.getUrlEncoder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.standalone.StandaloneLoginConfig;
import io.leitstand.security.crypto.Secret;

@RunWith(MockitoJUnitRunner.class)
public class AccessKeyEncodingServiceTest {

	private static final UserName USER_ID = UserName.valueOf("JUNIT");
	
	@Mock
	private StandaloneLoginConfig config;
	
	@InjectMocks
	private AccessKeyEncodingService service = new AccessKeyEncodingService();
	
	
	@Before
	public void mockSignature() {
		when(config.apiKeyHmac(anyString())).thenAnswer(new Answer() {

			@Override
			public Object answer(InvocationOnMock invocation) throws Throwable {
				String token = (String) invocation.getArguments()[0];
				return getUrlEncoder().encodeToString(hmacSha256(new Secret("changeit".getBytes())).sign(token));
			}
			
		});
	}
	
	@Test
	public void can_encode_decode_scopes() {
		ApiAccessKey accessKey = newApiAccessKey()
								 .withId(randomAccessKeyId())
								 .withUserName(USER_ID)
								 .withScopes("foo","bar")
								 .withDateCreated(new Date())
								 .build();
		String encoded = service.encode(accessKey);
		ApiAccessKey decoded = service.decode(encoded);
		assertEquals(accessKey,decoded);
	}
	
	@Test
	public void can_encode_decode_temporary() {
		ApiAccessKey accessKey = newApiAccessKey()
								 .withId(randomAccessKeyId())
								 .withUserName(USER_ID)
								 .withTemporaryAccess(true)
								 .withDateCreated(new Date())
								 .build();
		String encoded = service.encode(accessKey);
		ApiAccessKey decoded = service.decode(encoded);
		assertEquals(accessKey,decoded);
		assertTrue(decoded.isTemporary());
	}
	
	@Test
	public void can_encode_decode_complete_temporary_key() {
		ApiAccessKey accessKey = newApiAccessKey()
								 .withId(randomAccessKeyId())
								 .withUserName(USER_ID)
								 .withScopes("foo","bar")
								 .withTemporaryAccess(true)
								 .withDateCreated(new Date())
								 .build();
		String encoded = service.encode(accessKey);
		ApiAccessKey decoded = service.decode(encoded);
		assertEquals(accessKey,decoded);
		assertEquals(asSet("foo","bar"),accessKey.getScopes());
		assertTrue(decoded.isTemporary());
	}
	
	@Test
	public void can_encode_decode_complete_longtime_key() {
		ApiAccessKey accessKey = newApiAccessKey()
								 .withId(randomAccessKeyId())
								 .withUserName(USER_ID)
								 .withScopes("foo","bar")
								 .withTemporaryAccess(false)
								 .withDateCreated(new Date())
								 .build();
		String encoded = service.encode(accessKey);
		ApiAccessKey decoded = service.decode(encoded);
		assertEquals(accessKey,decoded);
		assertEquals(asSet("foo","bar"),accessKey.getScopes());
		assertFalse(decoded.isTemporary());
	}
	
}
