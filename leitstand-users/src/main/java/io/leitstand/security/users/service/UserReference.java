/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.auth.UserId;

public class UserReference extends ValueObject{

	public static Builder newUserReference() {
		return new Builder();
	}
	
	protected static class UserReferenceBuilder<T extends UserReference,B extends UserReferenceBuilder<T,B>>{
		
		protected T instance;
		
		protected UserReferenceBuilder(T instance) {
			this.instance = instance;
		}
		
		public B withUuid(String uuid) {
			assertNotInvalidated(getClass(), instance);
			((UserReference)instance).uuid = uuid;
			return (B) this;
		}

		public B withUserId(UserId userId) {
			assertNotInvalidated(getClass(), instance);
			((UserReference)instance).userId = userId;
			return (B) this;
		}

		public B withGivenName(String givenName) {
			assertNotInvalidated(getClass(), instance);
			((UserReference)instance).givenName = givenName;
			return (B) this;
		}
		
		public B withSurname(String surName) {
			assertNotInvalidated(getClass(), instance);
			((UserReference)instance).surname = surName;
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
	
	private String uuid;
	@Valid
	@NotNull(message="{user_id.required}")
	private UserId userId;
	private String givenName;
	private String surname;
	@Valid
	private EmailAddress email;
	
	public String getUuid() {
		return uuid;
	}
	
	public UserId getUserId() {
		return userId;
	}
	
	public String getGivenName() {
		return givenName;
	}
	
	public String getSurname() {
		return surname;
	}
	
	public EmailAddress getEmail() {
		return email;
	}
	
}
