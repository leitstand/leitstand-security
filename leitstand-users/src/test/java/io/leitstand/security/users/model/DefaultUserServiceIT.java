/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.model;

import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.security.users.service.ReasonCode.IDM0004E_USER_NOT_FOUND;
import static io.leitstand.security.users.service.ReasonCode.IDM0008E_PASSWORD_MISMATCH;
import static io.leitstand.security.users.service.UserSettings.newUserSettings;
import static io.leitstand.security.users.service.UserSubmission.newUserSubmission;
import static java.lang.Boolean.TRUE;
import static java.util.UUID.randomUUID;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.Principal;

import javax.security.enterprise.credential.Password;
import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.commons.db.DatabaseService;
import io.leitstand.commons.messages.Message;
import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.model.Repository;
import io.leitstand.security.auth.UserId;
import io.leitstand.security.users.service.EmailAddress;
import io.leitstand.security.users.service.UserSettings;
import io.leitstand.security.users.service.UserSubmission;

public class DefaultUserServiceIT extends UsersIT {

	
	private DefaultUserService service;
	private ArgumentCaptor<Message> message;
	
	private HttpServletRequest context;
	
	@Before
	public void initTestResources() {
		Repository repository = new Repository(getEntityManager());
		DatabaseService db = getDatabase();
		Messages messages = mock(Messages.class);
		message = ArgumentCaptor.forClass(Message.class);
		doNothing().when(messages).add(message.capture());
		PasswordService hashing = new PasswordService();
		context = mock(HttpServletRequest.class);
		service = new DefaultUserService(repository,db,hashing,messages,context);
		
		transaction(()->{
			repository.merge(new Role(1L,"Administrator"));
			repository.merge(new Role(2L,"Operator"));
		});
		
	}
	
	@Test
	public void cannot_create_user_with_invalid_password_confirmation() {
		UserSubmission user = newUserSubmission()
							  .withUserId(UserId.valueOf("wrong_confirm"))
							  .withPassword(new Password("unittest"))
							  .withConfirmedPassword(new Password("mismatch"))
							  .build();
		
		transaction(()->{
			service.addUser(user);
		});
		assertEquals(IDM0008E_PASSWORD_MISMATCH.getReasonCode(),message.getValue().getReason());
		
	}
	
	@Test
	public void can_create_user_with_valid_password_confirmation() {
		UserSubmission user = newUserSubmission()
							  .withUuid(randomUUID().toString())
							  .withUserId(UserId.valueOf("create_user"))
							  .withGivenName("Jane")
							  .withSurname("Doe")
							  .withRoles("Administrator","Operator")
							  .withEmailAddress(EmailAddress.valueOf("jane.doe@leitstand.io"))
							  .withPassword(new Password("unittest"))
							  .withConfirmedPassword(new Password("unittest"))
							  .build();
		
		transaction(()->{
			service.addUser(user);
		});
		
		transaction(() -> {
			UserSettings settings = service.getUser(UserId.valueOf("create_user"));
			assertEquals(user.getUserId(),settings.getUserId());
			assertEquals(user.getUuid(),settings.getUuid());
			assertEquals(user.getGivenName(),settings.getGivenName());
			assertEquals(user.getSurname(),settings.getSurname());
			assertEquals(user.getEmail(),settings.getEmail());
			assertEquals(user.getRoles(),settings.getRoles());
		});
 	}
	
	@Test
	public void cannot_update_non_existent_user() {
		UserSettings user = newUserSettings()
							  .withUserId(UserId.valueOf("unknown"))
							  .withGivenName("Jane")
							  .withSurname("Doe")
							  .withRoles("Administrator","Operator")
							  .withEmailAddress(EmailAddress.valueOf("jane.doe@leitstand.io"))
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
		
		when(context.isUserInRole("Administrator")).thenReturn(TRUE);
		UserSubmission user = newUserSubmission()
							  .withUuid(randomUUID().toString())
							  .withUserId(UserId.valueOf("updated_user"))
							  .withGivenName("Jane")
							  .withSurname("Doe")
							  .withRoles("Administrator","Operator")
							  .withEmailAddress(EmailAddress.valueOf("jane.doe@leitstand.io"))
							  .withPassword(new Password("unittest"))
							  .withConfirmedPassword(new Password("unittest"))
							  .build();
		
		transaction(()->{
			service.addUser(user);
		});
		
		transaction(() -> {
			UserSettings settings = service.getUser(UserId.valueOf("updated_user"));
			assertEquals(user.getUserId(),settings.getUserId());
			assertEquals(user.getUuid(),settings.getUuid());
			assertEquals(user.getGivenName(),settings.getGivenName());
			assertEquals(user.getSurname(),settings.getSurname());
			assertEquals(user.getEmail(),settings.getEmail());
			assertEquals(user.getRoles(),settings.getRoles());
			
			settings = newUserSettings()
					   .withUuid(user.getUuid())
					   .withUserId(UserId.valueOf("updated_user"))
					   .withGivenName("John")
					   .withSurname("Doe")
					   .withRoles("Operator")
					   .withEmailAddress(EmailAddress.valueOf("jane.doe@leitstand.io"))
					   .build();
			
			service.storeUserSettings(settings);
			
		});
		
		transaction(() -> {
			UserSettings settings = service.getUser(UserId.valueOf("updated_user"));
			assertEquals(user.getUserId(),settings.getUserId());
			assertEquals(user.getUuid(),settings.getUuid());
			assertEquals("John",settings.getGivenName());
			assertEquals(user.getSurname(),settings.getSurname());
			assertEquals(user.getEmail(),settings.getEmail());
			assertEquals(asSet("Operator"),settings.getRoles());
		});
 	}
	
	@Test
	public void user_can_update_own_settings() {
		
		Principal principal = mock(Principal.class);
		when(principal.getName()).thenReturn("user");
		when(context.getUserPrincipal()).thenReturn(principal);
		UserSubmission user = newUserSubmission()
							  .withUuid(randomUUID().toString())
							  .withUserId(UserId.valueOf("user"))
							  .withGivenName("Jane")
							  .withSurname("Doe")
							  .withRoles("Operator")
							  .withEmailAddress(EmailAddress.valueOf("jane.doe@leitstand.io"))
							  .withPassword(new Password("unittest"))
							  .withConfirmedPassword(new Password("unittest"))
							  .build();
		
		transaction(()->{
			service.addUser(user);
		});
		
		transaction(() -> {
			UserSettings settings = service.getUser(UserId.valueOf("user"));
			assertEquals(user.getUserId(),settings.getUserId());
			assertEquals(user.getUuid(),settings.getUuid());
			assertEquals(user.getGivenName(),settings.getGivenName());
			assertEquals(user.getSurname(),settings.getSurname());
			assertEquals(user.getEmail(),settings.getEmail());
			assertEquals(user.getRoles(),settings.getRoles());
			
			settings = newUserSettings()
					   .withUuid(user.getUuid())
					   .withUserId(UserId.valueOf("user"))
					   .withGivenName("John")
					   .withSurname("Doe")
					   .withRoles("Operator","Administrator")
					   .withEmailAddress(EmailAddress.valueOf("jane.doe@leitstand.io"))
					   .build();
			
			service.storeUserSettings(settings);
			
		});
		
		transaction(() -> {
			UserSettings settings = service.getUser(UserId.valueOf("user"));
			assertEquals(user.getUserId(),settings.getUserId());
			assertEquals(user.getUuid(),settings.getUuid());
			assertEquals("John",settings.getGivenName());
			assertEquals(user.getSurname(),settings.getSurname());
			assertEquals(user.getEmail(),settings.getEmail());
			assertEquals(asSet("Operator"),settings.getRoles());
		});
 	}
	
}
