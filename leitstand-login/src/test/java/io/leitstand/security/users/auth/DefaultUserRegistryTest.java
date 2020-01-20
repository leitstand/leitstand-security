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
package io.leitstand.security.users.auth;

import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.users.service.ReasonCode.IDM0004E_USER_NOT_FOUND;
import static io.leitstand.security.users.service.UserSettings.newUserSettings;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import javax.security.enterprise.credential.Password;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.user.UserInfo;
import io.leitstand.security.users.service.UserService;
import io.leitstand.security.users.service.UserSettings;

@RunWith(MockitoJUnitRunner.class)
public class DefaultUserRegistryTest {

	@Mock
	private UserService users;
	
	@InjectMocks
	private DefaultUserRegistry registry = new DefaultUserRegistry();
	
	@Test
	public void return_null_when_user_does_not_exist() {
		UserName userName = userName("UnitTest");
		when(users.getUser(userName)).thenThrow(new EntityNotFoundException(IDM0004E_USER_NOT_FOUND));
		assertNull(registry.getUserInfo(userName));
	}
	
	@Test
	public void return_user_info_when_user_exists() {
		UserName userName = userName("UnitTest");
		UserSettings settings = newUserSettings()
								.withUserName(userName)
								.withRoles("Administrator","Operator")
								.build();
		when(users.getUser(userName)).thenReturn(settings);
		UserInfo userInfo = registry.getUserInfo(userName);
		assertEquals(userName,userInfo.getUserName());
		assertTrue(userInfo.getRoles().contains("Operator"));
		assertTrue(userInfo.getRoles().contains("Administrator"));
	}
	
	@Test
	public void reject_login_attempt_with_invalid_credentials() {
		UserName userName = userName("UnitTest");
		Password passwd = new Password("password");
		when(users.isValidPassword(userName, passwd)).thenReturn(FALSE);
		assertEquals(INVALID_RESULT,registry.validateCredentials(new UsernamePasswordCredential("UnitTest", passwd)));
	}
	
	@Test
	public void accept_login_attempt_with_invalid_credentials() {
		UserName userName = userName("UnitTest");
		UserSettings settings = newUserSettings()
								.withUserName(userName)
								.withRoles("Administrator","Operator")
								.build();
		Password passwd = new Password("password");
		when(users.getUser(userName)).thenReturn(settings);		
		when(users.isValidPassword(userName, passwd)).thenReturn(TRUE);
		CredentialValidationResult result = registry.validateCredentials(new UsernamePasswordCredential("UnitTest", passwd));
		assertEquals("UnitTest",result.getCallerPrincipal().getName());
		assertTrue(result.getCallerGroups().contains("Administrator"));
		assertTrue(result.getCallerGroups().contains("Operator"));
	}
	
}
