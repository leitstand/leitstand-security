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
package io.leitstand.security.sso.graylog;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;

import java.util.Set;
import java.util.TreeSet;

import javax.json.bind.annotation.JsonbProperty;
import javax.json.bind.annotation.JsonbTypeAdapter;

import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.jsonb.UserNameAdapter;

public class UserInfo extends ValueObject{

	public static Builder newUserInfo() {
		return new Builder();
	}
	
	public static class Builder {
		private UserInfo userInfo = new UserInfo();
		
		public Builder withName(String name) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.name = name;
			return this;
		}

		public Builder withSurname(String name) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.surname = name;
			return this;
		}
		
		public Builder withUsername(UserName name) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.username = name;
			return this;
		}
		
		public Builder withEmail(String email) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.email = email;
			return this;
		}
		
		public Builder withRoles(Set<String> roles) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.roles = unmodifiableSet(new TreeSet<>(roles));
			return this;
		}
		
		public UserInfo build() {
			try {
				assertNotInvalidated(getClass(), userInfo);
				return userInfo;
			} finally {
				this.userInfo = null;
			}
		}

	}
	
	private String name;
	private String surname;
	@JsonbTypeAdapter(UserNameAdapter.class)
	private UserName username;
	private String email;
	@JsonbProperty("role_ids")
	private Set<String> roles = emptySet();
	//Graylog requires that groups must not be null. Hence we use an empty groups.
	private Set<String> groups = emptySet();
	
	public String getName() {
		return name;
	}
	
	public String getSurname() {
		return surname;
	}
	public UserName getUsername() {
		return username;
	}
	
	public String getEmail() {
		return email;
	}
	public Set<String> getRoles() {
		return roles;
	}
	
	public Set<String> getGroups() {
		return groups;
	}
	
}
