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
package io.leitstand.security.auth.accesskey;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;
import static io.leitstand.commons.model.ObjectUtil.asSet;
import static io.leitstand.security.auth.accesskey.AccessKeyId.randomAccessKeyId;
import static java.lang.System.currentTimeMillis;
import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;

import java.util.Date;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

import javax.json.bind.annotation.JsonbTypeAdapter;

import io.leitstand.commons.jsonb.DateToLongAdapter;
import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserName;

public class ApiAccessKey extends ValueObject {
	
	public static Builder newApiAccessKey() {
		return new Builder();
	}
	
	public static Builder newApiAccessKey(ApiAccessKey template) {
		Builder builder = new Builder();
		builder.key.userName = template.getUserName();
		return builder;
	}
	
	public static class Builder {
		
		private ApiAccessKey key = new ApiAccessKey();
		
		public Builder withId(AccessKeyId accessKeyId) {
			assertNotInvalidated(getClass(), key);
			key.id = accessKeyId;
			return this;
		}
		
		public Builder withUserName(UserName userName) {
			assertNotInvalidated(getClass(),  key);
			key.userName = userName;
			return this;
		}
		
		public Builder withScopes(String... scopes) {
			return withScopes(asSet(scopes));
		}
		
		public Builder withScopes(Set<String> scopes) {
			assertNotInvalidated(getClass(),key);
			key.scopes = new TreeSet<>(scopes);
			return this;
		}
		
		public Builder withDateCreated(Date dateCreated) {
			assertNotInvalidated(getClass(), key);
			key.dateCreated = new Date(dateCreated.getTime());
			return this;
		}
		
		public Builder withTemporaryAccess(boolean temporaryAccess) {
			assertNotInvalidated(getClass(), key);
			key.temporaryAccess = temporaryAccess;
			return this;
		}
		
		public ApiAccessKey build() {
			try {
				assertNotInvalidated(getClass(), key);
				if(key.dateCreated == null) {
					key.dateCreated = new Date();
				}
				return key;
			} finally {
				this.key = null;
			}
		}
		
	}
	
		   
	private AccessKeyId id = randomAccessKeyId();
	
	private UserName userName;
	
	@JsonbTypeAdapter(DateToLongAdapter.class)
	private Date dateCreated;
	
	private Set<String> scopes = emptySet();
	
	private boolean temporaryAccess;
	
	
	public AccessKeyId getId() {
		return id;
	}
	
	public UserName getUserName() {
		return userName;
	}
	
	public Date getDateCreated() {
		return new Date(dateCreated.getTime());
	}
	
	public boolean isTemporary() {
		return temporaryAccess;
	}
	
	public Set<String> getScopes() {
		return unmodifiableSet(scopes);
	}

	public boolean isOlderThan(int duration, TimeUnit unit) {
		return dateCreated.getTime() + unit.toMillis(duration) < currentTimeMillis();
	}

}
