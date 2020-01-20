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
