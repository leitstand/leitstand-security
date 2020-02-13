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

import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.leitstand.security.auth.UserName;

/**
 * The <code>AccessTokenManager</code> validates the access token associated with the current HTTP request.
 * <p>
 * Leitstand iterates over all existing access token managers until a first authentication manager accepts or declines the current request 
 * or issues an access token respectively.
 * All remaining access token managers which have not yet been invoked will not be called.
 */
public interface AccessTokenManager {

	/**
	 * Validates the access token of the current request.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @return {@link CredentialResult#INVALID_RESULT} if an invalid access token was specified,
	 *         {@link CredentialResult#NOT_VALIDATED_RESULT} if no access token was specified,
	 *         and a <code>CredentialResult</code> with user and role information if the credentials were valid.
	 */
	CredentialValidationResult validateAccessToken(HttpServletRequest request, 
												   HttpServletResponse response);

	/**
	 * Invalidates the access token associated with the specified request.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 */
	default void invalidateAccessToken(HttpServletRequest request, HttpServletResponse response) {}
	
	/**
	 * Issues an access token for the authenticated user.
	 * Returns <code>false</code> if no access token was issued, <code>true</code> otherwise.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @param userName the user name of the authenticated user
	 * @return <code>true</code> if an access token was issued, <code>false</code> otherwise.
	 */
	default boolean issueAccessToken(HttpServletRequest request, 
							 		 HttpServletResponse response, 
							 		 UserName userName) {
		return false;
	}
	
	
}
