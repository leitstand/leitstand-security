/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.auth;

import static io.leitstand.security.auth.user.UserInfo.newUserInfo;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.security.enterprise.credential.Password;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;

import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.security.auth.UserId;
import io.leitstand.security.auth.user.UserInfo;
import io.leitstand.security.auth.user.UserRegistry;
import io.leitstand.security.users.service.UserService;
import io.leitstand.security.users.service.UserSettings;

@Dependent
public class DefaultUserRegistry implements UserRegistry{

	@Inject
	private UserService users;
	
	@Override
	public UserInfo getUserInfo(UserId userId) {
		try {
			UserSettings user = users.getUser(userId);
			return newUserInfo()
				   .withUserId(user.getUserId())
				   .withRoles(user.getRoles())
				   .withAccessTokenTtl(user.getAccessTokenTtl(), 
						   		   	   user.getAccessTokenTtlUnit())
				   .build();
		} catch(EntityNotFoundException e) {
			return null;
		}
	}

	@Override
	public CredentialValidationResult validateCredentials(UsernamePasswordCredential credentials) {
		UserId   userId = UserId.valueOf(credentials.getCaller());
		Password passwd = credentials.getPassword(); 
		if(users.isValidPassword(userId,passwd)){
			UserInfo user = getUserInfo(userId);
			return new CredentialValidationResult(userId.toString(),user.getRoles());
		}
		return INVALID_RESULT;
	}

	
}
