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

import static io.leitstand.commons.model.ObjectUtil.asSet;
import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;

import java.util.Set;

import javax.enterprise.context.RequestScoped;

import io.leitstand.security.auth.UserContext;
import io.leitstand.security.auth.UserName;

/**
 * The <code>UserContextProvider</code> is a request-scoped CDI bean that provides the <code>UserContext</code> of the authenticated user.
 * @author mast
 *
 */
@RequestScoped
public class UserContextProvider implements UserContext{

	private UserName userName;
	private Set<String> scopes = emptySet();
	private boolean sealed;
	
	
	/**
	 * Sets the user name of the authenticated user.
	 * @param userName the user name of the authenticated user.
	 */
	public void setUserName(UserName userName) {
		if(sealed) {
			throw new IllegalStateException("Cannot change user name of a sealed user context!");
		}
		this.userName = userName;
	}
	
	/**
	 * Sets the scopes the authenticated user can access.
	 * @param scopes the accessible scopes.
	 */
	public void setScopes(Set<String> scopes) {
		if(sealed) {
			throw new IllegalStateException("Cannot change scopes of a sealed user context!");
		}
		this.scopes = scopes;
	}
	
	/**
	 * Seals the user context to make it immutable.
	 * Attempts to modify a sealed user context raise an exception.
	 */
	public void seal() {
		this.sealed = true;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public UserName getUserName() {
		return userName;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Set<String> getScopes(){
		return unmodifiableSet(scopes);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isUnauthenticated() {
		return userName == null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean scopesIncludeOneOf(String... scopes) {
		if(scopes.length == 0) {
			return !isUnauthenticated();
		}
		for(String scope : scopes) {
			if(this.scopes.contains(scope)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Sets the scopes the user is authorized to access.
	 * @param scopes the accessible scopes.
	 */
	public void setScopes(String... scopes) {
		setScopes(asSet(scopes));
	}

	
}
