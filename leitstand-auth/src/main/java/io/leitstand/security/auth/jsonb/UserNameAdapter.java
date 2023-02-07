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
package io.leitstand.security.auth.jsonb;

import javax.json.bind.adapter.JsonbAdapter;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.auth.UserName;

/**
 * <code>UserName</code> JSON-B adapter.
 */
public class UserNameAdapter implements JsonbAdapter<UserName,String> {

	/**
	 * Creates a <code>UserName</code> from the given string.
	 * @param name the user name
	 * @return the typed user name or <code>null</code> if the given string is <code>null</code> or empty.
	 */
	@Override
	public UserName adaptFromJson(String name) throws Exception {
		return UserName.valueOf(name);
	}

	/**
	 * Converts a <code>UserName</code> to a string.
	 * @param name the user name
	 * @return the string representation of the user name or <code>null</code> if the given string is <code>null</code> or empty.
	 */
	@Override
	public String adaptToJson(UserName name) throws Exception {
		return Scalar.toString(name);
	}

}
