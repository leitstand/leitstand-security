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
import static io.leitstand.security.auth.UserId.randomUserId;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserId;
import io.leitstand.security.auth.UserName;

public class UserReference extends ValueObject{

	public static Builder newUserReference() {
		return new Builder();
	}
	
	protected static class UserReferenceBuilder<T extends UserReference,B extends UserReferenceBuilder<T,B>>{
		
		protected T instance;
		
		protected UserReferenceBuilder(T instance) {
			this.instance = instance;
		}
		
		public B withUserId(UserId userId) {
			assertNotInvalidated(getClass(), instance);
			((UserReference)instance).userId = userId;
			return (B) this;
		}

		public B withUserName(UserName userName) {
			assertNotInvalidated(getClass(), instance);
			((UserReference)instance).userName = userName;
			return (B) this;
		}

		public B withGivenName(String givenName) {
			assertNotInvalidated(getClass(), instance);
			((UserReference)instance).givenName = givenName;
			return (B) this;
		}
		
		public B withFamilyName(String surName) {
			assertNotInvalidated(getClass(), instance);
			((UserReference)instance).familyName = surName;
			return (B) this;
		}
		
		public B withEmailAddress(EmailAddress email) {
			assertNotInvalidated(getClass(), instance);
			((UserReference)instance).email = email;
			return (B) this;
		}
		
		public T build() {
			try {
				assertNotInvalidated(getClass(), instance);
				return this.instance;
			} finally {
				this.instance = null;
			}
		}
	}

	public static class Builder extends UserReferenceBuilder<UserReference, Builder>{
		public Builder() {
			super(new UserReference());
		}
	}
	
	private UserId userId = randomUserId();
	@Valid
	@NotNull(message="{user_name.required}")
	private UserName userName;
	private String givenName;
	private String familyName;
	private boolean oidcOnly;
	@Valid
	private EmailAddress email;
	
	public UserId getUserId() {
		return userId;
	}
	
	public UserName getUserName() {
		return userName;
	}
	
	public String getGivenName() {
		return givenName;
	}
	
	public String getFamilyName() {
		return familyName;
	}
	
	public EmailAddress getEmail() {
		return email;
	}
	
	public boolean isOidcOnly() {
		return oidcOnly;
	}
	
}
