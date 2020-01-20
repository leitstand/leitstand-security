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
