/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.rs;

import javax.json.bind.annotation.JsonbTypeAdapter;
import javax.security.enterprise.credential.Password;
import javax.validation.constraints.NotNull;

import io.leitstand.security.users.jsonb.PasswordAdapter;

/**
 * A request to change the user's current password.
 * <p>
 * A user must specify the current password and the new password to change their password.
 */
public class ChangePasswordRequest extends ResetPasswordRequest{

	@JsonbTypeAdapter(PasswordAdapter.class)
	@NotNull(message="{password.required}")
	private Password password;

	/**
	 * Returns the user's current password.
	 * @return the user's current password.
	 */
	public Password getPassword() {
		return password;
	}
	
}