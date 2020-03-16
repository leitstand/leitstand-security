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
import static io.leitstand.security.auth.user.UserInfo.newUserInfo;
import static java.util.Collections.emptySet;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.security.enterprise.credential.Password;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;

import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.user.UserInfo;
import io.leitstand.security.auth.user.UserRegistry;
import io.leitstand.security.users.service.UserService;
import io.leitstand.security.users.service.UserSettings;

@Dependent
public class DefaultUserRegistry implements UserRegistry{

	@Inject
	private UserService users;
	
	@Override
	public UserInfo getUserInfo(UserName userName) {
		try {
			UserSettings user = users.getUser(userName);
			return newUserInfo()
				   .withUserName(user.getUserName())
				   .withScopes(user.getScopes())
				   .withAccessTokenTtl(user.getAccessTokenTtl(), 
						   		   	   user.getAccessTokenTtlUnit())
				   .build();
		} catch(EntityNotFoundException e) {
			return null;
		}
	}

	@Override
	public CredentialValidationResult validateCredentials(UsernamePasswordCredential credentials) {
		UserName userName = userName(credentials.getCaller());
		Password passwd = credentials.getPassword(); 
		if(users.isValidPassword(userName,passwd)){
			UserSettings user = users.getUser(userName);
			return new CredentialValidationResult(getClass().getName(), 
												  userName.toString(),
												  null,
												  user.getUserId().toString(),
												  emptySet());
		}
		return INVALID_RESULT;
	}

	
}
