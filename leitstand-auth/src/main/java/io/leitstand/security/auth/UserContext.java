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
package io.leitstand.security.auth;

import java.util.Set;

/**
 * The request-scoped CDI-managed <code>UserContext</code> provides information about the authenticated user.
 */
public interface UserContext {

	/**
	 * Returns the user name of the authenticated user.
	 * @return the user name of the authenticated user.
	 */
	UserName getUserName();
	/**
	 * Returns the scopes the user is authorized to access.
	 * @return the scopes the user is authorized to access.
	 */
	Set<String> getScopes();
	
	/**
	 * Returns whether the current request is unauthenticated.
	 * @return <code>true</code> when the request is an unauthenticated request.
	 */
	boolean isUnauthenticated();
	
	/**
	 * Tests whether the user is allowed to access at least one of the given scopes.
	 * @param scopes the scopes to be tested for access
	 * @return <code>true</code> if the user is allowed to access at least one of the given scopes, <code>false</code> otherwise.
	 */
	boolean scopesIncludeOneOf(String... scopes);
}
