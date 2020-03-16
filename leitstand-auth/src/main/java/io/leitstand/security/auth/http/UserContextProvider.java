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
import io.leitstand.security.auth.UserId;
import io.leitstand.security.auth.UserName;

@RequestScoped
public class UserContextProvider implements UserContext{

	private UserId userId;
	private UserName userName;
	private Set<String> scopes = emptySet();
	private boolean sealed;
	
	
	public void setUserId(UserId userId) {
		if(sealed) {
			throw new IllegalStateException("Cannot change user ID of a sealed user context!");
		}
		this.userId = userId;
		
	}
	
	public void setUserName(UserName userName) {
		if(sealed) {
			throw new IllegalStateException("Cannot change user name of a sealed user context!");
		}
		this.userName = userName;
	}
	
	public void setScopes(Set<String> scopes) {
		if(sealed) {
			throw new IllegalStateException("Cannot change scopes of a sealed user context!");
		}
		this.scopes = scopes;
	}
	
	public void seal() {
		this.sealed = true;
	}
	
	@Override
	public UserId getUserId() {
		return userId;
	}
	
	@Override
	public UserName getUserName() {
		return userName;
	}
	
	@Override
	public Set<String> getScopes(){
		return unmodifiableSet(scopes);
	}

	public void setName(String name) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean isUnauthenticated() {
		return userName == null;
	}

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

	public void setScopes(String... scopes) {
		setScopes(asSet(scopes));
	}
	
}
