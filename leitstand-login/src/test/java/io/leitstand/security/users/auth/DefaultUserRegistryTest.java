/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.auth;

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
import io.leitstand.security.auth.UserId;
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
		UserId userId = UserId.valueOf("UnitTest");
		when(users.getUser(userId)).thenThrow(new EntityNotFoundException(IDM0004E_USER_NOT_FOUND));
		assertNull(registry.getUserInfo(userId));
	}
	
	@Test
	public void return_user_info_when_user_exists() {
		UserId userId = UserId.valueOf("UnitTest");
		UserSettings settings = newUserSettings()
								.withUserId(userId)
								.withRoles("Administrator","Operator")
								.build();
		when(users.getUser(userId)).thenReturn(settings);
		UserInfo userInfo = registry.getUserInfo(userId);
		assertEquals(userId,userInfo.getUserId());
		assertTrue(userInfo.getRoles().contains("Operator"));
		assertTrue(userInfo.getRoles().contains("Administrator"));
	}
	
	@Test
	public void reject_login_attempt_with_invalid_credentials() {
		UserId 	 userId = UserId.valueOf("UnitTest");
		Password passwd = new Password("password");
		when(users.isValidPassword(userId, passwd)).thenReturn(FALSE);
		assertEquals(INVALID_RESULT,registry.validateCredentials(new UsernamePasswordCredential("UnitTest", passwd)));
	}
	
	@Test
	public void accept_login_attempt_with_invalid_credentials() {
		UserId userId = UserId.valueOf("UnitTest");
		UserSettings settings = newUserSettings()
								.withUserId(userId)
								.withRoles("Administrator","Operator")
								.build();
		Password passwd = new Password("password");
		when(users.getUser(userId)).thenReturn(settings);		
		when(users.isValidPassword(userId, passwd)).thenReturn(TRUE);
		CredentialValidationResult result = registry.validateCredentials(new UsernamePasswordCredential("UnitTest", passwd));
		assertEquals("UnitTest",result.getCallerPrincipal().getName());
		assertTrue(result.getCallerGroups().contains("Administrator"));
		assertTrue(result.getCallerGroups().contains("Operator"));
	}
	
}
