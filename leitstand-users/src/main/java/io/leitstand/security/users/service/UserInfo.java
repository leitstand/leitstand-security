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
package io.leitstand.security.users.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.commons.model.ObjectUtil.asSet;
import static java.util.Collections.emptySet;

import java.util.Set;
import java.util.concurrent.TimeUnit;

import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserName;

public class UserInfo extends ValueObject{

	public static Builder newUserInfo() {
		return new Builder();
	}
	
	public static class Builder {
		private UserInfo userInfo = new UserInfo();
		
		public Builder withUserName(UserName userName) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.userName = userName;
			return this;
		}
				
		public Builder withScopes(String... scopes) {
			return withScopes(asSet(scopes));
		}
		
		public Builder withScopes(Set<String> scopes) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.scopes = scopes;
			return this;
		}
		
		public Builder withAccessTokenTtl(Long duration, TimeUnit unit) {
			assertNotInvalidated(getClass(), userInfo);
			userInfo.accessTokenTtl = duration;
			userInfo.accessTokenTtlUnit = unit;
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
	
	private UserName userName;
	private Set<String> scopes = emptySet();
	private Long accessTokenTtl;
	private TimeUnit accessTokenTtlUnit;

	public UserName getUserName() {
		return userName;
	}
	
	public Set<String> getScopes() {
		return scopes;
	}
	
	public Long getAccessTokenTtl() {
		return accessTokenTtl;
	}
	
	public TimeUnit getAccessTokenTtlUnit() {
		return accessTokenTtlUnit;
	}
	
}
