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

import javax.json.bind.adapter.JsonbAdapter;

import io.leitstand.security.users.service.UserId;

/**
 * <code>UserId</code> JSON-B adapter.
 */
public class UserIdAdapter implements JsonbAdapter<UserId,String> {

	/**
	 * Creates a <code>UserId</code> from the given string.
	 * @param id the user ID
	 * @return the typed user ID or <code>null</code> if the given string is <code>null</code> or empty.
	 */
	@Override
	public UserId adaptFromJson(String id) throws Exception {
		return UserId.valueOf(id);
	}

	/**
	 * Converts a <code>UserId</code> to a string.
	 * @param id the user Id
	 * @return the string representation of the user ID or <code>null</code> if the given user ID is <code>null</code>.
	 */
	@Override
	public String adaptToJson(UserId id) throws Exception {
		return UserId.toString(id);
	}

}
