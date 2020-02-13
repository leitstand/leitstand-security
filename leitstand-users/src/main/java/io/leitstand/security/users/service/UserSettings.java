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
import static java.util.Collections.unmodifiableSet;

import java.util.Date;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

/**
 * The user settings of a Leitstand user.
 * <p>
 * Use <code>{@literal @Inject} {@literal @Authenticated} UserSettings</code> to obtain
 * the settings of the authenticated user 
 * or <code>{@literal @Inject} {@literal @Authenticated} UserId</code> to get the user ID
 * of the authenticated user.
 *  
 */
public class UserSettings extends UserReference{
	
	public static Builder newUserSettings() {
		return new Builder();
	}
	
	public static class UserSettingsBuilder<T extends UserSettings, B extends UserSettingsBuilder<T,B>> extends UserReferenceBuilder<UserSettings, B  >{
		
		public UserSettingsBuilder(T object) {
			super(object);
		}
		
		public B withDateCreated(Date date) {
			assertNotInvalidated(getClass(), instance);
			instance.dateCreated = new Date(date.getTime());
			return (B) this;
		}
		
		public B withDateModified(Date date) {
			assertNotInvalidated(getClass(), instance);
			instance.dateModified = new Date(date.getTime());
			return (B) this;
		}
		
		public B withRoles(RoleName... roles) {
			return withRoles(asSet(roles));
		}
		
		public B withAccessTokenTtl(long duration, TimeUnit unit) {
			assertNotInvalidated(getClass(), instance);
			instance.accessTokenTtl = duration;
			instance.accessTokenTtlUnit = unit;
			return (B) this;
		}

		public B withRoles(Set<RoleName> roles) {
			assertNotInvalidated(getClass(), instance);
			instance.roles = new TreeSet<>(roles);
			return (B) this;
		}

		public B withScopes(String... scopes) {
			return withScopes(asSet(scopes));
		}
		
		public B withScopes(Set<String> scopes) {
			assertNotInvalidated(getClass(), instance);
			instance.scopes = new TreeSet<>(scopes);
			return (B) this;
		}
		
	}
	
	public static class Builder extends UserSettingsBuilder<UserSettings,Builder> {
		public Builder() {
			super(new UserSettings());
		}
	}
	
	private Date   dateCreated;
	private Date   dateModified;
	private Long   accessTokenTtl;
	private TimeUnit accessTokenTtlUnit;
	private Set<RoleName> roles = emptySet();
	private Set<String> scopes = emptySet();
	
	public Date getDateCreated() {
		if(dateCreated != null) {
			return new Date(dateCreated.getTime());
		}
		return null;
	}
	
	public Date getDateModified() {
		if(dateModified != null) {
			return new Date(dateModified.getTime());
		}
		return null;
	}
	
	public Set<RoleName> getRoles(){
		return unmodifiableSet(roles);
	}
	
	public Set<String> getScopes() {
		return unmodifiableSet(scopes);
	}

	public Long getAccessTokenTtl() {
		return accessTokenTtl;
	}
	
	public TimeUnit getAccessTokenTtlUnit() {
		return accessTokenTtlUnit;
	}
	
	public boolean isCustomAccessTokenTtl() {
		return accessTokenTtl != null && accessTokenTtlUnit != null;
	}
}
