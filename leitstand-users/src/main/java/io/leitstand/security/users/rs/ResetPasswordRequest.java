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
package io.leitstand.security.users.rs;

import javax.json.bind.annotation.JsonbTypeAdapter;
import javax.security.enterprise.credential.Password;
import javax.validation.constraints.NotNull;

import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.users.jsonb.PasswordAdapter;

/**
 * A request to reset the user's current password.
 * <p>
 */
public class ResetPasswordRequest extends ValueObject{

	@JsonbTypeAdapter(PasswordAdapter.class)
	@NotNull(message="{new_password.required}")
	private Password newPassword;
	
	@JsonbTypeAdapter(PasswordAdapter.class)
	@NotNull(message="{confirmed_password.required}")
	private Password confirmedPassword;
	
	
	/**
	 * Returns the user's new password.
	 * @return the user's new password.
	 */
	public Password getNewPassword() {
		return newPassword;
	}
	
	/** 
	 * Returns the confirmed password for typo detection.
	 * New password and confirmed password must be equal.
	 * @return the confirmed password.
	 */
	public Password getConfirmedPassword() {
		return confirmedPassword;
	}
	
}
