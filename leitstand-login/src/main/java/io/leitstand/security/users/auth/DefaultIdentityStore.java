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

import static java.util.Collections.emptySet;

import java.util.Set;

import javax.inject.Inject;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;

import io.leitstand.commons.model.Service;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.user.UserInfo;
import io.leitstand.security.auth.user.UserRegistry;

/**
 * A Java EE <code>IdentityStore</code> implementation for the built-in identity management.
 * <p>
 * This implementation forwards all invocation to the {@link UserRegistry} to verify given credentials 
 * and load the group memberships of an authenticated user, which are  the user's roles.
 * </p>
 */
@Service
public class DefaultIdentityStore implements IdentityStore {

	@Inject
	private UserRegistry users;
	
	/**
	 * Uses the caller unique ID to read the user settings from the default user repository and
	 * returns the user's roles as caller groups.
	 * 
	 * {@inheritDoc}
	 * 
	 * @see UserRegistry#getUserInfo(UserName)
	 * @see UserInfo#getRoles()
	 */
	@Override
	public Set<String> getCallerGroups(CredentialValidationResult validationResult) {
		UserInfo user = users.getUserInfo(UserName.valueOf(validationResult.getCallerUniqueId()));
		if(user != null) {
			return user.getRoles();
		}
		return emptySet();
	}
		
	
	/**
	 * Passes the user credentials to the default user repository in order to validate them.
	 * This method supports <code>UsernamePasswordCredential</code> credentials only.
	 * {@inheritDoc}
	 */
	@Override
	public CredentialValidationResult validate(Credential credential) {
		return users.validateCredentials((UsernamePasswordCredential)credential);
	}
}
