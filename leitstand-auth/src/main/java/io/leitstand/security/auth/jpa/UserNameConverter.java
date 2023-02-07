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
package io.leitstand.security.auth.jpa;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.auth.UserName;


/**
 * <code>UserName</code> JPA converter.
 */
@Converter(autoApply=true)
public class UserNameConverter implements AttributeConverter<UserName, String>{

	/**
	 * Converts a <code>UserName</code> to a string.
	 * @param userName the user name
	 * @return the string representation of a user name or <code>null</code> if the <code>UserName</code> is <code>null</code>.
	 */
	@Override
	public String convertToDatabaseColumn(UserName userName) {
		return Scalar.toString(userName);
	}

	/**
	 * Creates a <code>UserName</code> from a string.
	 * @param userName the user name
	 * @return the typed user name or <code>null</code> if the given string is <code>null</code> or empty.
	 */
	@Override
	public UserName convertToEntityAttribute(String userName) {
		return UserName.valueOf(userName);
	}
	
}
