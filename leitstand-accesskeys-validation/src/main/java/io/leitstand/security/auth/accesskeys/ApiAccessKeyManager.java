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
package io.leitstand.security.auth.accesskeys;

import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.accesskey.ApiAccessKeyDecoder;
import io.leitstand.security.auth.http.AccessTokenManager;
import io.leitstand.security.auth.http.Authorization;
import io.leitstand.security.auth.standalone.StandaloneLoginConfig;

@Dependent
public class ApiAccessKeyManager implements AccessTokenManager {
	
	@Inject
	private ApiAccessKeyDecoder accesskeys;
	
	@Inject
	private AccessKeyValidator authenticator;

	@Inject
	private StandaloneLoginConfig loginConfig;
	
	/**
	 * Decodes and validates a bearer token authorization
	 * @param request - the HTTP request
	 * @param response - the HTTP response
	 * @param auth - the Authorization HTTP header.
	 * @return <code>INVALID_RESULT</code> if the provided access key is invalid, 
	 * <code>NOT_VALIDATED_RESULT</Code> if the authorization header does not contain a bearer token and
	 * information about the authenticated user if the access key is valid.
	 */
	public CredentialValidationResult validateAccessToken(HttpServletRequest request, 
													 	  HttpServletResponse response) {
		if(!loginConfig.isApiAccessKeysEnabled()) {
			return NOT_VALIDATED_RESULT;
		}
		Authorization auth = Authorization.valueOf(request);
		if(auth != null && auth.isBearerToken() && accesskeys.isApiAccessKey(auth.getCredentials())) {
			try {
				ApiAccessKey accessKey = accesskeys.decode(auth.getCredentials());
				if(authenticator.isValid(request,accessKey)) {
					return new CredentialValidationResult(accessKey.getUserName().toString());
				}
				return INVALID_RESULT;
			} catch (AccessDeniedException e) {
				return INVALID_RESULT;
			}
		}
		return NOT_VALIDATED_RESULT;
	}
}
