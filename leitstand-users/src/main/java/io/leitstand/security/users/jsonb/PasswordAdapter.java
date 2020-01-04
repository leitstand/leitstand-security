/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.jsonb;

import static io.leitstand.commons.model.StringUtil.isEmptyString;

import javax.json.bind.adapter.JsonbAdapter;
import javax.security.enterprise.credential.Password;

public class PasswordAdapter implements JsonbAdapter<Password, String> {

	/**
	 * Converts the given password to a string. 
	 * Returns <code>null</code> if the given email address is <code>null</code>.
	 * @param obj - the password to be converted
	 * @return the string representation of the given password
	 */
	@Override
	public String adaptToJson(Password obj) throws Exception {
		return obj != null ? obj.toString() : null;
	}

	
	/**
	 * Converts the specified string to a password
	 * Returns <code>null</code> if the string is <code>null</code> or empty.
	 * @param obj - the string value to be converted
	 * @return the specified string as password
	 */
	@Override
	public Password adaptFromJson(String obj) throws Exception {
		if(isEmptyString(obj)) {
			return null;
		}
		return new Password(obj);
	}
	
}
