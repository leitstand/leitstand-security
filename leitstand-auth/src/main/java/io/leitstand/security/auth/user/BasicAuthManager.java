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

import static io.leitstand.security.auth.UserId.userId;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.http.Authorization.authorization;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.leitstand.security.auth.http.AccessTokenManager;
import io.leitstand.security.auth.http.Authorization;
import io.leitstand.security.auth.http.BasicAuthentication;
import io.leitstand.security.auth.http.UserContextProvider;
import io.leitstand.security.auth.standalone.StandaloneLoginConfig;

/**
 * The <code>BasicAuthManager</code> processes a request with HTTP Basic Authentication 
 * by means of
 * decoding the user credentials from the <code>Authorization</code> HTTP header and
 * verification of the user exists and the supplied password is correct.
 */
@Dependent
public class BasicAuthManager implements AccessTokenManager{

	@Inject
	private IdentityStore is;
	
	@Inject
	private StandaloneLoginConfig config;
	
	@Inject
	private UserContextProvider userContext;

	@Inject
	private UserRegistry users;
	
	/**
	 * 
	 * @param request
	 * @param response
	 * @param auth
	 * @return
	 */
	public CredentialValidationResult validateAccessToken(HttpServletRequest request, 
														  HttpServletResponse response) {
		
		Authorization auth = authorization(request);
		if(auth != null && auth.isBasic()) {
			if(!config.isBasicAuthEnabled()) {
				userContext.seal();
				return INVALID_RESULT;
			}
			BasicAuthentication basic = new BasicAuthentication(auth);
			CredentialValidationResult result = is.validate(new UsernamePasswordCredential(basic.getUserName().toString(), 
															basic.getPassword()));
			if(result.getStatus() == VALID) {
				UserInfo user = users.getUserInfo(basic.getUserName());
				userContext.setUserId(userId(result.getCallerUniqueId()));
				userContext.setUserName(userName(result.getCallerPrincipal()));
				userContext.setScopes(user.getScopes());
			}
			userContext.seal();
			return result;
		}
		return NOT_VALIDATED_RESULT;
	}
	
}
