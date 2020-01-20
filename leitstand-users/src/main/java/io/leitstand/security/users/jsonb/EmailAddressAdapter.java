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

import io.leitstand.security.users.service.EmailAddress;

/**
 * Converters a {@link EmailAddress} to a string an vice versa.
 */
public class EmailAddressAdapter implements JsonbAdapter<EmailAddress, String> {

	/**
	 * Converts the given email address to a string. 
	 * Returns <code>null</code> if the given email address is <code>null</code>.
	 * @param attribute - the email address to be converted
	 * @return the string representation of the given email address
	 */
	@Override
	public String adaptToJson(EmailAddress obj) throws Exception {
		return EmailAddress.toString(obj);
	}

	/**
	 * Converts the specified string to an email address.
	 * Returns <code>null</code> if the string is <code>null</code> or empty.
	 * @param obj - the string value to be converted
	 * @return the specified string as email address
	 */
	@Override
	public EmailAddress adaptFromJson(String obj) throws Exception {
		return EmailAddress.valueOf(obj);
	}

}
