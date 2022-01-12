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
package io.leitstand.security.users.model;

import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.users.model.PasswordService.ITERATIONS;
import static io.leitstand.security.users.model.UserSettingsMother.newOperator;
import static io.leitstand.security.users.service.EmailAddress.emailAddress;
import static io.leitstand.security.users.service.ReasonCode.IDM0005E_INCORRECT_PASSWORD;
import static io.leitstand.security.users.service.ReasonCode.IDM0007E_ADMIN_PRIVILEGES_REQUIRED;
import static io.leitstand.security.users.service.ReasonCode.IDM0008E_PASSWORD_MISMATCH;
import static io.leitstand.security.users.service.UserId.randomUserId;
import static io.leitstand.security.users.service.UserSettings.newUserSettings;
import static io.leitstand.security.users.service.UserSubmission.newUserSubmission;
import static io.leitstand.testing.ut.LeitstandCoreMatchers.reason;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.util.Arrays.asList;
import static java.util.concurrent.TimeUnit.HOURS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.security.enterprise.credential.Password;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.UnprocessableEntityException;
import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.model.Query;
import io.leitstand.commons.model.Repository;
import io.leitstand.security.auth.UserContext;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.users.service.EmailAddress;
import io.leitstand.security.users.service.UserId;
import io.leitstand.security.users.service.UserSettings;
import io.leitstand.security.users.service.UserSubmission;

@RunWith(MockitoJUnitRunner.class)
public class DefaultUserServiceTest {
	
	@Rule
	public ExpectedException exception = ExpectedException.none();
	
	
	@Mock
	private Repository repository;
	
	@Mock
	private Messages messages;
	
	@Mock
	private PasswordService hashing;
	
	@Mock
	private UserContext userContext;
	
	@InjectMocks
	private DefaultUserService service = new DefaultUserService();
	
	private static final UserId AUTHENTICATED = randomUserId();
	private static final UserName USER = userName("user");
	
	@Test
	public void create_new_user_with_custom_ttl() {
		byte[] SALT = new byte[ITERATIONS];
		Password password = new Password("test");
		when(hashing.salt()).thenReturn(SALT);
		when(hashing.hash(password, SALT, ITERATIONS)).thenReturn(new byte[] {1,2});
		ArgumentCaptor<User> user = ArgumentCaptor.forClass(User.class);
		doNothing().when(repository).add(user.capture());
		UserSubmission submission = newUserSubmission()
									.withUserName(UserName.valueOf("non-existent-user"))
									.withPassword(password)
									.withConfirmedPassword(password)
									.withAccessTokenTtl(10, HOURS)
									.build();
		
		service.addUser(submission);
		User newUser = user.getValue();
		assertNotNull(newUser.getUserId());
		assertEquals(submission.getUserName(),
					 newUser.getUserName());
		assertEquals(HOURS,newUser.getTokenTtlUnit());
		assertEquals(10,newUser.getTokenTtl());
		
	}
	
	@Test
	public void create_new_user_with_default_token_ttl() {
		byte[] SALT = new byte[ITERATIONS];
		Password password = new Password("test");
		when(hashing.salt()).thenReturn(SALT);
		when(hashing.hash(password, SALT, ITERATIONS)).thenReturn(new byte[] {1,2});
		ArgumentCaptor<User> user = ArgumentCaptor.forClass(User.class);
		doNothing().when(repository).add(user.capture());
		UserSubmission submission = newUserSubmission()
									.withUserName(UserName.valueOf("non-existent-user"))
									.withPassword(password)
									.withConfirmedPassword(password)
									.build();
		
		service.addUser(submission);
		User newUser = user.getValue();
		assertNotNull(newUser.getUserId());
		assertEquals(submission.getUserName(),
					 newUser.getUserName());
		assertNull(newUser.getTokenTtlUnit());
		assertEquals(0,newUser.getTokenTtl());
		
	}
	
	@Test
	public void non_admin_user_cannot_modify_other_user() {
		exception.expect(AccessDeniedException.class);
		exception.expect(reason(IDM0007E_ADMIN_PRIVILEGES_REQUIRED));
		User user = mock(User.class);
		when(userContext.getUserName()).thenReturn(userName("other"));
		when(repository.execute(any(Query.class)))
					   .thenReturn(user);
		service.storeUserSettings(newOperator("unittest"));
	}
	
	@Test
	public void admin_user_can_modify_other_user() {
		
		when(userContext.scopesIncludeOneOf("adm")).thenReturn(true);
		User user = mock(User.class);
		Role role = mock(Role.class);
		when(user.getUserName()).thenReturn(new UserName("other"));
		
		when(repository.execute(any(Query.class)))
					   .thenReturn(user)
					   .thenReturn(role);

		
		UserSettings settings = newOperator("other");
		service.storeUserSettings(settings);
		verify(user).setUserName(settings.getUserName());
		verify(user).setEmailAddress(settings.getEmail());
		verify(user).setGivenName(settings.getGivenName());
		verify(user).setFamilyName(settings.getFamilyName());
		verify(user).setRoles(asList(role));
	}
	
	@Test
	public void non_admin_user_can_modify_its_own_settings() {
		User user = mock(User.class);
		when(user.getUserId()).thenReturn(AUTHENTICATED);
		when(user.getUserName()).thenReturn(USER);
		when(userContext.scopesIncludeOneOf("adm")).thenReturn(false);
		when(userContext.getUserName()).thenReturn(USER);
		when(repository.execute(any(Query.class))).thenReturn(user);

		UserSettings settings = newUserSettings()
								.withUserId(AUTHENTICATED)
								.withUserName(USER)
								.withGivenName("John")
								.withFamilyName("Doe")
								.withEmailAddress(emailAddress("john.doe@acme.com"))
								.build();
		service.storeUserSettings(settings);
		verify(user).setUserName(settings.getUserName());
		verify(user).setEmailAddress(settings.getEmail());
		verify(user).setGivenName(settings.getGivenName());
		verify(user).setFamilyName(settings.getFamilyName());
	}
	
	@Test
	public void cannot_change_password_if_both_passwords_are_different() {
		byte[] salt = new byte[0];
		byte[] hash = new byte[0];
		Password current = new Password("current");
		Password newpass = new Password("newpass");
		Password confirm = new Password("confirm");
		UserName userId = UserName.valueOf("unittest");
		User user = mock(User.class);
		when(user.getSalt()).thenReturn(salt);
		when(user.getPasswordHash()).thenReturn(hash);
		when(repository.execute(any(Query.class))).thenReturn(user);
		when(hashing.isExpectedPassword(current, 
										salt, 
										hash, 
										user.getIterations()))
		.thenReturn(TRUE);
		try {
			service.setPassword(userId, current, newpass, confirm);
			fail("Exception expected!");
		} catch(UnprocessableEntityException e) {
			assertEquals(IDM0008E_PASSWORD_MISMATCH,e.getReason());
		}
		verify(user,never()).setPassword(any(byte[].class), any(byte[].class), anyInt());
	}
	
	@Test
	public void cannot_change_password_if_current_password_is_wrong() {
		byte[] salt = new byte[0];
		byte[] hash = new byte[0];
		Password current = new Password("current");
		Password newpass = new Password("newpass");
		Password confirm = new Password("newpass");
		UserName userId = UserName.valueOf("unittest");
		User user = mock(User.class);
		when(user.getSalt()).thenReturn(salt);
		when(user.getPasswordHash()).thenReturn(hash);
		when(repository.execute(any(Query.class))).thenReturn(user);
		when(hashing.isExpectedPassword(current, 
										salt, 
										hash, 
										user.getIterations()))
		.thenReturn(FALSE);
		try {
			service.setPassword(userId, current, newpass, confirm);
			fail("Exception expected!");
		} catch(UnprocessableEntityException e) {
			assertEquals(IDM0005E_INCORRECT_PASSWORD,e.getReason());
		}
		verify(user,never()).setPassword(any(byte[].class), any(byte[].class), anyInt());		
	}
	
	@Test
	public void can_change_password_if_current_password_and_confirmation_is_correct() {
		byte[] salt = new byte[0];
		byte[] hash = new byte[0];
		byte[] newhash = new byte[0];

		Password current = new Password("current");
		Password newpass = new Password("newpass");
		Password confirm = new Password("newpass");
		UserName userId = UserName.valueOf("unittest");
		User user = mock(User.class);
		when(user.getSalt()).thenReturn(salt);
		when(user.getPasswordHash()).thenReturn(hash);
		when(repository.execute(any(Query.class))).thenReturn(user);
		when(hashing.isExpectedPassword(current, 
										salt, 
										hash, 
										user.getIterations()))
		.thenReturn(TRUE);
		when(hashing.salt()).thenReturn(salt);
		when(hashing.hash(newpass, salt, ITERATIONS)).thenReturn(newhash);
		service.setPassword(userId, current, newpass, confirm);
		
		verify(user).setPassword(newhash,salt,ITERATIONS);
		
	}
	
	@Test
	public void password_is_invalid_for_unknown_user() {
		Password password = new Password("secret");
		assertFalse(service.isValidPassword(UserName.valueOf("unknown"),
											password));
		verify(hashing,never()).isExpectedPassword(eq(password), 
												   any(byte[].class), 
												   any(byte[].class), 
												   anyInt());
	}
	
	@Test
	public void verify_password_for_known_user() {
		byte[] salt = new byte[0];
		byte[] hash = new byte[0];

		Password password = new Password("secret");
		UserName userId = UserName.valueOf("unittest");
		User user = mock(User.class);
		when(repository.execute(any(Query.class))).thenReturn(user);
		when(user.getSalt()).thenReturn(salt);
		when(user.getPasswordHash()).thenReturn(hash);
		when(user.getIterations()).thenReturn(ITERATIONS);
		when(hashing.isExpectedPassword(password, 
										salt, 
										hash, 
										ITERATIONS))
		.thenReturn(TRUE);
		assertTrue(service.isValidPassword(userId,password));
	}

}
