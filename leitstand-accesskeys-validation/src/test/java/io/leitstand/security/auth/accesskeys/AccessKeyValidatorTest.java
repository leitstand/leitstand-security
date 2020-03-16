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
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.accesskey.AccessKeyId.randomAccessKeyId;
import static java.lang.Boolean.TRUE;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
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
import io.leitstand.security.auth.http.UserContextProvider;

@RunWith(MockitoJUnitRunner.class)
public class AccessKeyValidatorTest {

	
	@Mock
	private DatabaseService db;
	
	@Mock
	private UserContextProvider context;
	
	
	@InjectMocks
	private AccessKeyValidator validator = new AccessKeyValidator();
	private HttpServletRequest request;
	private ApiAccessKey key;
	private AccessKeyId keyId;
	
	@Before
	public void initValidator() {
		validator.initStateCheckCache();
		keyId = randomAccessKeyId();
		key = mock(ApiAccessKey.class);
		when(key.getScopes()).thenReturn(asSet("element"));
		when(key.getId()).thenReturn(keyId);
		when(key.getUserName()).thenReturn(userName("unittest"));
		when(db.getSingleResult(any(), any())).thenReturn(keyId.toString());
		request = mock(HttpServletRequest.class);
		when(request.getMethod()).thenReturn("post");
		when(request.getRequestURI()).thenReturn("/junit");
	}
	
	@Test
	public void accept_non_revoked_access_key() {
		assertTrue(validator.isValid(request, key));
		
		verify(context).setScopes(asSet("element"));
		verify(context).setUserName(userName("unittest"));
	}
	
	@Test
	public void reject_access_key_not_in_accesskeys_list() {
		reset(db); // Drop all known access keys
		assertFalse(validator.isValid(request,
									    key));
	}
	
	@Test
	public void accept_temporary_access_key_if_not_expired() {
		when(key.getDateCreated()).thenReturn(new Date());
		when(key.isTemporary()).thenReturn(TRUE);
		
		assertTrue(validator.isValid(request, key));
	}
	
	@Test
	public void reject_expired_temporary_access_key() {
		when(key.isTemporary()).thenReturn(TRUE);
		when(key.isOlderThan(60, SECONDS)).thenReturn(TRUE);
		assertFalse(validator.isValid(request, key));
	}
	
	@Test
	public void deny_access_for_revoked_access_key() {
		reset(db);
		assertFalse(validator.isValid(request, key));
	}
	
	@Test
	public void create_access_key_state_on_demand() {
		AccessKeyValidator.AccessKeyState state = validator.getKeyState(keyId);
		assertNotNull(state);
		assertSame(state,validator.getKeyState(keyId));
	}
	
}
