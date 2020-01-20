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
package io.leitstand.security.auth.http;

import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
	
	/**
	 * 
	 * @param request
	 * @param response
	 * @param auth
	 * @return
	 */
	public CredentialValidationResult validateAccessToken(HttpServletRequest request, 
														  HttpServletResponse response) {
			
		Authorization auth = Authorization.valueOf(request);
		if(auth != null && auth.isBasic()) {
			BasicAuthentication basic = new BasicAuthentication(auth);
			return is.validate(new UsernamePasswordCredential(basic.getUserName().toString(), 
														 	  basic.getPassword()));
		}
		return NOT_VALIDATED_RESULT;
	}
	
}
