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
package io.leitstand.security.accesskeys.model;

import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0101E_MALFORMED_ACCESSKEY;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.accesskeys.AccessKeyId.randomAccessKeyId;
import static io.leitstand.security.auth.accesskeys.ApiAccessKey.newApiAccessKey;
import static io.leitstand.testing.ut.LeitstandCoreMatchers.reason;
import static java.util.Base64.getEncoder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.Date;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.UnprocessableEntityException;
import io.leitstand.commons.etc.Environment;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.accesskeys.ApiAccessKey;

@RunWith(MockitoJUnitRunner.class)
public class AccessKeyEncodingServiceTest {

   	private static final UserName USER_ID = userName("JUNIT");
	
    @Rule
    public TemporaryFolder envFolder = new TemporaryFolder();
   	
    @Rule
    public ExpectedException exception = ExpectedException.none();
	
	private DefaultApiAccessKeyService service;
	
	
	@Before
	public void mockSignature() throws IOException {
	    File baseDir = envFolder.newFolder();
	    Environment env  = new Environment(baseDir);
	    AccessKeyConfig config = new AccessKeyConfig(env);
	    service = new DefaultApiAccessKeyService(config);
	}
	
    @Test
    public void report_invalid_base64_characters_as_malformed_token() {
        exception.expect(UnprocessableEntityException.class);
        exception.expect(reason(AKY0101E_MALFORMED_ACCESSKEY));
        service.decode("no:base:64");
    }
    
    @Test
    public void report_malformed_token() {
        exception.expect(AccessDeniedException.class);
        exception.expect(reason(AKY0101E_MALFORMED_ACCESSKEY));
        service.decode(getEncoder().encodeToString(toUtf8Bytes("malformed_token")));
    }
    
    @Test
    public void report_missing_signature_as_malformed_token() {
        exception.expect(AccessDeniedException.class);
        exception.expect(reason(AKY0101E_MALFORMED_ACCESSKEY));
        service.decode(getEncoder().encodeToString(toUtf8Bytes("no_signature:")));
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
		System.out.println(encoded);
		ApiAccessKey decoded = service.decode(encoded);
		assertEquals(accessKey,decoded);
	}
	
	@Test
	public void can_encode_decode_temporary() {
		ApiAccessKey accessKey = newApiAccessKey()
								 .withId(randomAccessKeyId())
								 .withUserName(USER_ID)
								 .withDateCreated(new Date())
								 .withTemporaryAccess(true)
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
