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

import static io.leitstand.security.auth.accesskey.AccessKeyId.randomAccessKeyId;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.commons.db.DatabaseService;
import io.leitstand.security.auth.accesskey.AccessKeyId;
import io.leitstand.security.auth.accesskey.ApiAccessKey;

@RunWith(MockitoJUnitRunner.class)
public class AccessKeyAuthenticatorTest {

	
	@Mock
	private DatabaseService db;
	@InjectMocks
	private AccessKeyAuthenticator validator = new AccessKeyAuthenticator();
	private HttpServletRequest request;
	private ApiAccessKey key;
	private AccessKeyId keyId;
	
	@Before
	public void initValidator() {
		validator.initStateCheckCache();
		keyId = randomAccessKeyId();
		key = mock(ApiAccessKey.class);
		when(key.getId()).thenReturn(keyId);
		DatabaseService db = mock(DatabaseService.class);
		when(db.getSingleResult(any(), any())).thenReturn(keyId.toString());
		request = mock(HttpServletRequest.class);
		when(request.getMethod()).thenReturn("post");
		when(request.getRequestURI()).thenReturn("/junit");
	}
	
	@Test
	public void reject_access_key_not_in_accesskeys_list() {
		assertFalse(validator.isAllowed(request,
									    key));
	}
	
	@Test
	public void reject_access_key_if_method_is_not_allowed() {
		when(key.isPathAllowed(request.getRequestURI())).thenReturn(TRUE);
		when(key.isMethodAllowed(request.getMethod())).thenReturn(FALSE);
		assertFalse(validator.isAllowed(request, key));
	}
	
	@Test
	public void reject_access_key_if_path_is_not_allowed() {
		when(key.isPathAllowed(request.getRequestURI())).thenReturn(TRUE);
		when(key.isMethodAllowed(request.getMethod())).thenReturn(FALSE);
		assertFalse(validator.isAllowed(request, key));
	}
	
	
	@Test
	public void accept_temporary_access_key_if_not_expired() {
		when(key.getDateCreated()).thenReturn(new Date());
		when(key.isTemporary()).thenReturn(TRUE);
		
		when(key.isPathAllowed(request.getRequestURI())).thenReturn(TRUE);
		when(key.isMethodAllowed(request.getMethod())).thenReturn(TRUE);
		assertTrue(validator.isAllowed(request, key));
	}
	
	@Test
	public void reject_expired_temporary_access_key() {
		when(key.isTemporary()).thenReturn(TRUE);
		when(key.isOlderThan(60, SECONDS)).thenReturn(TRUE);
		when(key.isPathAllowed(request.getRequestURI())).thenReturn(TRUE);
		when(key.isMethodAllowed(request.getMethod())).thenReturn(TRUE);
		assertFalse(validator.isAllowed(request, key));
	}
	
	@Test
	public void deny_access_for_revoked_access_key() {
		reset(db);
		when(key.isPathAllowed(request.getRequestURI())).thenReturn(TRUE);
		when(key.isMethodAllowed(request.getMethod())).thenReturn(TRUE);
		assertFalse(validator.isAllowed(request, key));
	}
	
	@Test
	public void create_access_key_state_on_demand() {
		AccessKeyAuthenticator.AccessKeyState state = validator.getKeyState(keyId);
		assertNotNull(state);
		assertSame(state,validator.getKeyState(keyId));
		
	}
	
}
