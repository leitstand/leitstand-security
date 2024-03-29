/*
4 * Copyright 2020 RtBrick Inc.
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

import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.users.model.Role.findRoleByName;
import static io.leitstand.security.users.service.EmailAddress.emailAddress;
import static io.leitstand.security.users.service.ReasonCode.IDM0004E_USER_NOT_FOUND;
import static io.leitstand.security.users.service.ReasonCode.IDM0008E_PASSWORD_MISMATCH;
import static io.leitstand.security.users.service.RoleId.randomRoleId;
import static io.leitstand.security.users.service.RoleName.roleName;
import static io.leitstand.security.users.service.UserId.randomUserId;
import static io.leitstand.security.users.service.UserSettings.newUserSettings;
import static io.leitstand.security.users.service.UserSubmission.newUserSubmission;
import static java.lang.Boolean.TRUE;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.security.enterprise.credential.Password;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.commons.UnprocessableEntityException;
import io.leitstand.commons.db.DatabaseService;
import io.leitstand.commons.messages.Message;
import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.model.Repository;
import io.leitstand.security.auth.UserContext;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.users.service.UserId;
import io.leitstand.security.users.service.UserSettings;
import io.leitstand.security.users.service.UserSubmission;
import io.leitstand.testing.ut.LeitstandCoreMatchers;

public class DefaultUserServiceIT extends UsersIT {

	@Rule
	public ExpectedException exception = ExpectedException.none();
	
	private DefaultUserService service;
	private ArgumentCaptor<Message> message;
	
	private UserContext context;
	
	@Before
	public void initTestResources() {
		Repository repository = new Repository(getEntityManager());
		DatabaseService db = getDatabase();
		Messages messages = mock(Messages.class);
		message = ArgumentCaptor.forClass(Message.class);
		doNothing().when(messages).add(message.capture());
		PasswordService hashing = new PasswordService();
		context = mock(UserContext.class);
		service = new DefaultUserService(repository,db,hashing,messages,context);
		
		transaction(()->{
			Role admin = repository.addIfAbsent(findRoleByName(roleName("Administrator")),
											    ()-> (new Role(randomRoleId(),roleName("Administrator"))));
			admin.setScopes(asSet("admin"));
			Role operator = repository.addIfAbsent(findRoleByName(roleName("Operator")),
												   ()-> (new Role(randomRoleId(),roleName("Operator"))));
			operator.setScopes(asSet("pod","element","metric","image"));
		});
		
	}
	
	@Test
	public void cannot_create_user_with_invalid_password_confirmation() {
		exception.expect(UnprocessableEntityException.class);
		exception.expect(LeitstandCoreMatchers.reason(IDM0008E_PASSWORD_MISMATCH));
		
		UserSubmission user = newUserSubmission()
							  .withUserName(UserName.valueOf("wrong_confirm"))
							  .withPassword(new Password("unittest"))
							  .withConfirmedPassword(new Password("mismatch"))
							  .build();
		
		transaction(()->{
			service.addUser(user);
		});
		
	}
	
	@Test
	public void can_create_user_with_valid_password_confirmation() {
		UserSubmission user = newUserSubmission()
							  .withUserId(randomUserId())
							  .withUserName(userName("create_user"))
							  .withGivenName("Jane")
							  .withFamilyName("Doe")
							  .withRoles(roleName("Administrator"),roleName("Operator"))
							  .withEmailAddress(emailAddress("jane.doe@leitstand.io"))
							  .withPassword(new Password("unittest"))
							  .withConfirmedPassword(new Password("unittest"))
							  .build();
		
		transaction(()->{
			service.addUser(user);
		});
		
		transaction(() -> {
			UserSettings settings = service.getUser(UserName.valueOf("create_user"));
			assertEquals(user.getUserName(),settings.getUserName());
			assertEquals(user.getUserId(),settings.getUserId());
			assertEquals(user.getGivenName(),settings.getGivenName());
			assertEquals(user.getFamilyName(),settings.getFamilyName());
			assertEquals(user.getEmail(),settings.getEmail());
			assertEquals(user.getRoles(),settings.getRoles());
		});
 	}
	
	@Test
	public void cannot_update_non_existent_user() {
		UserSettings user = newUserSettings()
							  .withUserName(UserName.valueOf("unknown"))
							  .withGivenName("Jane")
							  .withFamilyName("Doe")
							  .withRoles(roleName("Administrator"),roleName("Operator"))
							  .withEmailAddress(emailAddress("jane.doe@leitstand.io"))
							  .build();
		
		transaction(()->{
			try {
				service.storeUserSettings(user);
			} catch(EntityNotFoundException e) {
				assertEquals(IDM0004E_USER_NOT_FOUND,e.getReason());
			}
		});
	}
	
	@Test
	public void admin_can_update_existing_user() {
		
		when(context.scopesIncludeOneOf("adm")).thenReturn(TRUE);
		UserSubmission user = newUserSubmission()
							  .withUserId(randomUserId())
							  .withUserName(UserName.valueOf("updated_user"))
							  .withGivenName("Jane")
							  .withFamilyName("Doe")
							  .withRoles(roleName("Administrator"),roleName("Operator"))
							  .withEmailAddress(emailAddress("jane.doe@leitstand.io"))
							  .withPassword(new Password("unittest"))
							  .withConfirmedPassword(new Password("unittest"))
							  .build();
		
		transaction(()->{
			service.addUser(user);
		});
		
		transaction(() -> {
			UserSettings settings = service.getUser(UserName.valueOf("updated_user"));
			assertEquals(user.getUserName(),settings.getUserName());
			assertEquals(user.getUserId(),settings.getUserId());
			assertEquals(user.getGivenName(),settings.getGivenName());
			assertEquals(user.getFamilyName(),settings.getFamilyName());
			assertEquals(user.getEmail(),settings.getEmail());
			assertEquals(user.getRoles(),settings.getRoles());
			
			settings = newUserSettings()
					   .withUserId(user.getUserId())
					   .withUserName(UserName.valueOf("updated_user"))
					   .withGivenName("John")
					   .withFamilyName("Doe")
					   .withRoles(roleName("Operator"))
					   .withEmailAddress(emailAddress("jane.doe@leitstand.io"))
					   .build();
			
			service.storeUserSettings(settings);
			
		});
		
		transaction(() -> {
			UserSettings settings = service.getUser(UserName.valueOf("updated_user"));
			assertEquals(user.getUserName(),settings.getUserName());
			assertEquals(user.getUserId(),settings.getUserId());
			assertEquals("John",settings.getGivenName());
			assertEquals(user.getFamilyName(),settings.getFamilyName());
			assertEquals(user.getEmail(),settings.getEmail());
			assertEquals(asSet(roleName("Operator")),settings.getRoles());
		});
 	}
	
	@Test
	public void user_can_update_own_settings() {
		UserId userId = randomUserId();
		when(context.getUserName()).thenReturn(userName("user"));
		UserSubmission user = newUserSubmission()
							  .withUserId(userId)
							  .withUserName(userName("user"))
							  .withGivenName("Jane")
							  .withFamilyName("Doe")
							  .withRoles(roleName("Operator"))
							  .withEmailAddress(emailAddress("jane.doe@leitstand.io"))
							  .withPassword(new Password("unittest"))
							  .withConfirmedPassword(new Password("unittest"))
							  .build();
		
		transaction(()->{
			service.addUser(user);
		});
		
		transaction(() -> {
			UserSettings settings = service.getUser(userName("user"));
			assertEquals(user.getUserName(),settings.getUserName());
			assertEquals(user.getUserId(),settings.getUserId());
			assertEquals(user.getGivenName(),settings.getGivenName());
			assertEquals(user.getFamilyName(),settings.getFamilyName());
			assertEquals(user.getEmail(),settings.getEmail());
			assertEquals(user.getRoles(),settings.getRoles());
			
			settings = newUserSettings()
					   .withUserId(user.getUserId())
					   .withUserName(UserName.valueOf("user"))
					   .withGivenName("John")
					   .withFamilyName("Doe")
					   .withRoles(roleName("Operator"),roleName("Administrator"))
					   .withEmailAddress(emailAddress("jane.doe@leitstand.io"))
					   .build();
			
			service.storeUserSettings(settings);
			
		});
		
		transaction(() -> {
			UserSettings settings = service.getUser(UserName.valueOf("user"));
			assertEquals(user.getUserName(),settings.getUserName());
			assertEquals(user.getUserId(),settings.getUserId());
			assertEquals("John",settings.getGivenName());
			assertEquals(user.getFamilyName(),settings.getFamilyName());
			assertEquals(user.getEmail(),settings.getEmail());
			assertEquals(asSet(roleName("Operator")),settings.getRoles());
			assertEquals(asSet("pod","element","metric","image"),settings.getScopes());
		});
 	}
	
}
