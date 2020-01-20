/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.user;

import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;

import io.leitstand.security.auth.UserName;

public interface UserRegistry {

	/**
	 * Returns the user info for the specified user ID. 
	 * @param userName the user name
	 * @return the user and his associated roles or <code>null</code> if the user does not exist.
	 */
	UserInfo getUserInfo(UserName userName);
	CredentialValidationResult validateCredentials(UsernamePasswordCredential credentials);
	
}
