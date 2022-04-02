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

import static io.leitstand.security.auth.UserName.userName;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import io.leitstand.security.auth.http.UserContextProvider;
public class UserContextProviderTest {

	
	
	@Test
	public void unauthenticated_user_is_not_allowed_to_access_empty_scope() {
		UserContext unauthenticated = new UserContextProvider();
		assertFalse(unauthenticated.scopesIncludeOneOf());
	}
	
	@Test
	public void authenticated_user_is_allowed_to_access_empty_scope() {
		UserContextProvider authenticated = new UserContextProvider();
		authenticated.setUserName(userName("junit"));
		assertTrue(authenticated.scopesIncludeOneOf());
		
	}
	
	@Test
	public void user_is_allowd_to_access_included_scope() {
		UserContextProvider authenticated = new UserContextProvider();
		authenticated.setUserName(userName("junit"));
		authenticated.setScopes("a","b");
		assertTrue(authenticated.scopesIncludeOneOf("a","c"));

		
		
	}
	
	@Test
	public void user_is_not_allowed_to_access_non_included_scope() {
		UserContextProvider authenticated = new UserContextProvider();
		authenticated.setUserName(userName("junit"));
		authenticated.setScopes("a","b");
		assertFalse(authenticated.scopesIncludeOneOf("c","d"));
	}
	
}
