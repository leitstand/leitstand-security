/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.model;

import static io.leitstand.security.users.model.PasswordService.ITERATIONS;
import static io.leitstand.security.users.model.UserSettingsMother.newOperator;
import static io.leitstand.security.users.service.ReasonCode.IDM0005E_INCORRECT_PASSWORD;
import static io.leitstand.security.users.service.ReasonCode.IDM0008E_PASSWORD_MISMATCH;
import static io.leitstand.security.users.service.UserSubmission.newUserSubmission;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
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

import java.security.Principal;

import javax.security.enterprise.credential.Password;
import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
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
import io.leitstand.security.auth.UserId;
import io.leitstand.security.users.service.UserSettings;
import io.leitstand.security.users.service.UserSubmission;

@RunWith(MockitoJUnitRunner.class)
public class DefaultUserServiceTest {
	
	@Mock
	private HttpServletRequest context;
	
	@Mock
	private Repository repository;
	
	@Mock
	private Messages messages;
	
	@Mock
	private PasswordService hashing;
	
	@InjectMocks
	private DefaultUserService service = new DefaultUserService();
	
	private static final Principal AUTHENTICATED = new Principal() {

		@Override
		public String getName() {
			return "JUNIT";
		}
		
	};
	
	private static final Role OPERATOR = new Role(io.leitstand.security.auth.Role.OPERATOR);
	
	@Test
	public void admin_user_can_create_new_user() {
		when(context.isUserInRole("Administrator")).thenReturn(true);
		when(repository.execute(any(Query.class)))
					   .thenReturn(null)
					   .thenReturn(OPERATOR); // Role found
		byte[] SALT = new byte[ITERATIONS];
		Password password = new Password("test");
		when(hashing.salt()).thenReturn(SALT);
		when(hashing.hash(password, SALT, ITERATIONS)).thenReturn(new byte[] {1,2});
		ArgumentCaptor<User> user = ArgumentCaptor.forClass(User.class);
		doNothing().when(repository).add(user.capture());
		UserSubmission submission = newUserSubmission()
									.withUserId(UserId.valueOf("non-existent-user"))
									.withPassword(password)
									.withConfirmedPassword(password)
									.build();
		
		service.addUser(submission);
		User newUser = user.getValue();
		assertNotNull(newUser.getUuid());
		assertEquals(submission.getUserId(),
					 newUser.getUserId());
		
	}
	
	@Test(expected=AccessDeniedException.class)
	public void non_admin_user_cannot_modify_other_user() {
		when(repository.execute(any(Query.class))).thenReturn(new User(new UserId("other")));
		when(context.getUserPrincipal()).thenReturn(AUTHENTICATED);
		service.storeUserSettings(newOperator("other"));
	}
	
	@Test
	public void admin_user_can_modify_other_user() {
		when(context.isUserInRole("Administrator")).thenReturn(true);
		User user = mock(User.class);
		when(user.getUserId()).thenReturn(new UserId("other"));
		when(repository.execute(any(Query.class))).thenReturn(user).thenReturn(OPERATOR);
		when(context.getUserPrincipal()).thenReturn(AUTHENTICATED);
		
		UserSettings settings = newOperator("other");
		service.storeUserSettings(settings);
		verify(user).setUserId(settings.getUserId());
		verify(user).setEmailAddress(settings.getEmail());
		verify(user).setGivenName(settings.getGivenName());
		verify(user).setSurname(settings.getSurname());
	}
	
	@Test
	public void non_admin_user_can_modify_its_own_settings() {
		when(context.isUserInRole("Administrator")).thenReturn(true);
		User user = mock(User.class);
		when(user.getUserId()).thenReturn(UserId.valueOf(AUTHENTICATED));
		when(repository.execute(any(Query.class))).thenReturn(user).thenReturn(OPERATOR);
		when(context.getUserPrincipal()).thenReturn(AUTHENTICATED);
		
		UserSettings settings = newOperator(AUTHENTICATED);
		service.storeUserSettings(settings);
		verify(user).setUserId(settings.getUserId());
		verify(user).setEmailAddress(settings.getEmail());
		verify(user).setGivenName(settings.getGivenName());
		verify(user).setSurname(settings.getSurname());
	}
	
	@Test
	public void cannot_change_password_if_both_passwords_are_different() {
		byte[] salt = new byte[0];
		byte[] hash = new byte[0];
		Password current = new Password("current");
		Password newpass = new Password("newpass");
		Password confirm = new Password("confirm");
		UserId userId = UserId.valueOf("unittest");
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
		UserId userId = UserId.valueOf("unittest");
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
		UserId userId = UserId.valueOf("unittest");
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
		assertFalse(service.isValidPassword(UserId.valueOf("unknown"),
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
		UserId userId = UserId.valueOf("unittest");
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
