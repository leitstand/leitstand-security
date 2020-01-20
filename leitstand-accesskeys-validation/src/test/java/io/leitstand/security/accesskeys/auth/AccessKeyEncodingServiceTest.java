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

import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.auth.accesskey.AccessKeyId.randomAccessKeyId;
import static io.leitstand.security.auth.accesskey.ApiAccessKey.newApiAccessKey;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.jwt.JsonWebTokenConfig;
import io.leitstand.security.crypto.Secret;

@RunWith(MockitoJUnitRunner.class)
public class AccessKeyEncodingServiceTest {

	private static final UserName USER_ID = UserName.valueOf("JUNIT");
	
	@Mock
	private JsonWebTokenConfig config;
	
	@InjectMocks
	private AccessKeyEncodingService service = new AccessKeyEncodingService();
	
	@Before
	public void initServiceUnderTest() {
		when(config.getSecret()).thenReturn(new Secret(toUtf8Bytes("junit")));
		
	}
	
	@Test
	public void can_encode_decode_method() {
		ApiAccessKey accessKey = newApiAccessKey()
								 .withId(randomAccessKeyId())
								 .withUserName(USER_ID)
								 .withMethods("GET")
								 .withDateCreated(new Date())
								 .build();
		String encoded = service.encode(accessKey);
		ApiAccessKey decoded = service.decode(encoded);
		assertEquals(accessKey,decoded);
		
	}
	
	@Test
	public void can_encode_decode_methods() {
		ApiAccessKey accessKey = newApiAccessKey()
								 .withId(randomAccessKeyId())
								 .withUserName(USER_ID)
								 .withMethods("GET","PUT")
								 .withDateCreated(new Date())
								 .build();
		String encoded = service.encode(accessKey);
		ApiAccessKey decoded = service.decode(encoded);
		assertEquals(accessKey,decoded);
	}
	
	@Test
	public void can_encode_decode_paths() {
		ApiAccessKey accessKey = newApiAccessKey()
								 .withId(randomAccessKeyId())
								 .withUserName(USER_ID)
								 .withPaths("/api/v1/elements","/api/v1/images")
								 .withDateCreated(new Date())
								 .build();
		String encoded = service.encode(accessKey);
		ApiAccessKey decoded = service.decode(encoded);
		assertEquals(accessKey,decoded);
	}
	
	@Test
	public void can_encode_decode_path() {
		ApiAccessKey accessKey = newApiAccessKey()
								 .withId(randomAccessKeyId())
								 .withUserName(USER_ID)
								 .withPaths("/api/v1/elements")
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
								 .withMethods("GET","PUT","POST","DELETE")
								 .withPaths("/api/v1/elements","/api/v1/images")
								 .withTemporaryAccess(true)
								 .withDateCreated(new Date())
								 .build();
		String encoded = service.encode(accessKey);
		ApiAccessKey decoded = service.decode(encoded);
		assertEquals(accessKey,decoded);
		assertTrue(decoded.isMethodAllowed("GET"));
		assertTrue(decoded.isMethodAllowed("PUT"));
		assertTrue(decoded.isMethodAllowed("POST"));
		assertTrue(decoded.isMethodAllowed("DELETE"));
		assertTrue(decoded.isPathAllowed("/api/v1/elements"));
		assertTrue(decoded.isPathAllowed("/api/v1/images"));
		assertTrue(decoded.isTemporary());
	}
	
	@Test
	public void can_encode_decode_complete_longtime_key() {
		ApiAccessKey accessKey = newApiAccessKey()
								 .withId(randomAccessKeyId())
								 .withUserName(USER_ID)
								 .withMethods("GET","PUT","POST","DELETE")
								 .withPaths("/api/v1/elements","/api/v1/images")
								 .withTemporaryAccess(false)
								 .withDateCreated(new Date())
								 .build();
		String encoded = service.encode(accessKey);
		ApiAccessKey decoded = service.decode(encoded);
		assertEquals(accessKey,decoded);
		assertTrue(decoded.isMethodAllowed("GET"));
		assertTrue(decoded.isMethodAllowed("PUT"));
		assertTrue(decoded.isMethodAllowed("POST"));
		assertTrue(decoded.isMethodAllowed("DELETE"));
		assertTrue(decoded.isPathAllowed("/api/v1/elements"));
		assertTrue(decoded.isPathAllowed("/api/v1/images"));
		assertFalse(decoded.isTemporary());
	}
	
}
