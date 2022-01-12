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
package io.leitstand.security.sso.oidc.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.security.auth.UserName.userName;
import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;

import java.util.Set;
import java.util.TreeSet;

import javax.json.bind.annotation.JsonbTransient;

import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.users.service.EmailAddress;

public class OidcUserInfo extends ValueObject{

	public static Builder newUserInfo() {
		return new Builder();
	}
	
	public static class Builder {
		private OidcUserInfo userInfo = new OidcUserInfo();
		
		public Builder withName(String name) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.name = name;
			return this;
		}
		
		
		public Builder withSub(String sub) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.sub = sub;
			return this;
		}
		
		public Builder withPreferredUsername(String preferredUsername) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.preferredUsername = preferredUsername;
			return this;
		}
		
		public Builder withGivenName(String givenName) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.givenName = givenName;
			return this;
		}
		
		public Builder withFamilyName(String familyName) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.familyName = familyName;
			return this;
		}
		
		public Builder withScopes(String... scopes) {
			return withScopes(asSet(scopes));
		}
		
		public Builder withScopes(Set<String> scopes) {
			assertNotInvalidated(getClass(), userInfo);
			if(!scopes.isEmpty()) {
				userInfo.scopes = new TreeSet<>(scopes);
			}
			return this;
		}
		
		public Builder withEmail(EmailAddress email) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.email = email;
			return this;
		}
		
		public OidcUserInfo build() {
			try {
				assertNotInvalidated(getClass(), userInfo);
				return userInfo;
			} finally {
				this.userInfo = null;
			}
		}


	
	}
	
	private String name;
	private String sub;
	private String preferredUsername;
	private String givenName;
	private String familyName;
	private EmailAddress email;
	private Set<String> scopes = emptySet();
	
	public String getName() {
		return name;
	}
	
	public String getGivenName() {
		return givenName;
	}
	
	public String getFamilyName() {
		return familyName;
	}
	
	public String getSub() {
		return sub;
	}
	
	public String getPreferredUsername() {
		return preferredUsername;
	}
	
	public EmailAddress getEmail() {
		return email;
	}
	
	public Set<String> getScopes() {
		return unmodifiableSet(scopes);
	}
	

	@JsonbTransient
	public UserName getUserName() {
		UserName userName = userName(preferredUsername);
		if(userName == null) {
			return userName(sub);
		}
		return userName;
	}
	
}
