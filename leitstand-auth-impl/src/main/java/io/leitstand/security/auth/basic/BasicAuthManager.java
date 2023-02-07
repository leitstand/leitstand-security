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
package io.leitstand.security.auth.basic;

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
import io.leitstand.security.auth.user.UserRegistry;
import io.leitstand.security.users.service.UserInfo;

/**
 * The <code>BasicAuthManager</code> validates HTTP Basic Authentication credentials
 * by extracting the user name and the user's password and validating them against the
 * identity store.
 * <p>
 * Basic Authentication support is disabled by default and can be enabled by setting
 * the environment variable <code>BASIC_AUTH_ENABLED</code> to <code>true</code>.
 */
@Dependent
public class BasicAuthManager implements AccessTokenManager{

    private BasicAuthConfig config;
    
	private IdentityStore is;
	
	private UserContextProvider userContext;

	private UserRegistry users;
	
	protected BasicAuthManager() {
		// CDI
	}
	
	@Inject
	protected BasicAuthManager(IdentityStore is, UserRegistry users, UserContextProvider userContext, BasicAuthConfig config) {
		this.is = is;
		this.users = users;
		this.userContext = userContext;
		this.config = config;
	}

	/**
	 * Validates the Authorization HTTP header when the HTTP basic authorization scheme is used.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @return	<code>NOT_VALIDATED_RESULT</code> when not HTTP basic authorization credentials are found, <code>INVALID_RESULT</code> when the HTTP basic authentication is disabled or the credentials are invalid.
	 * and a <code>VALID</code> result when the basic credentials are valid and HTTP basic authorization is enabled.
	 */
	@Override
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
				userContext.setUserName(userName(result.getCallerPrincipal()));
				userContext.setScopes(user.getScopes());
			}
			userContext.seal();
			return result;
		}
		return NOT_VALIDATED_RESULT;
	}
	
}
