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

import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The <code>LoginManager</code> validates the credentials of a login request and 
 * logs the outcome of the validation in the login audit log.
 */
public interface LoginManager {
	
	/**
	 * Processes a login request and logs the login attempt outcome.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @return <code>INVALID_RESULT</code> if the provided credentials were invalid, 
	 * otherwise information about the authenticated user and its assigned roles
	 */
	CredentialValidationResult login(HttpServletRequest request, 
									 HttpServletResponse response);
		

}
