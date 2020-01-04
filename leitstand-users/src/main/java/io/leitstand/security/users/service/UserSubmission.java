/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.service;

import static io.leitstand.commons.model.BuilderUtil.assertNotInvalidated;

import javax.json.bind.annotation.JsonbTypeAdapter;
import javax.security.enterprise.credential.Password;
import javax.validation.constraints.NotNull;

import io.leitstand.security.users.jsonb.PasswordAdapter;

public class UserSubmission extends UserSettings {
	
	public static Builder newUserSubmission() {
		return new Builder();
	}
	
	public static class Builder extends UserSettingsBuilder<UserSubmission, Builder>{
		
		public Builder() {
			super(new UserSubmission());
		}
		
		
		public Builder withPassword(Password password) {
			assertNotInvalidated(getClass(), instance);
			((UserSubmission)instance).password =  password;
			return this;
		}
		
		public Builder withConfirmedPassword(Password confirmedPassword) {
			assertNotInvalidated(getClass(), instance);
			((UserSubmission)instance).confirmedPassword =  confirmedPassword;
			return this;
		}
		
		@Override
		public UserSubmission build() {
			return (UserSubmission) instance;
		}
		
	}

	
	@JsonbTypeAdapter(PasswordAdapter.class)
	@NotNull(message="{password.required}")
	private Password password;
	
	@JsonbTypeAdapter(PasswordAdapter.class)
	@NotNull(message="{confirmed_password.required}")
	private Password confirmedPassword;

	public Password getPassword() {
		return password;
	}
	
	public Password getConfirmedPassword() {
		return confirmedPassword;
	}


}