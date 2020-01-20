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
