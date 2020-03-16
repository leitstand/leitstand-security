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
package io.leitstand.security.users.jpa;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import io.leitstand.security.users.service.RoleName;

/**
 * Converters a {@link RoleName} to a string an vice versa.
 */
@Converter
public class RoleNameConverter implements AttributeConverter<RoleName, String>{

	/**
	 * Converts the a role name to a string. 
	 * Returns <code>null</code> if the given role name is <code>null</code>.
	 * @param attribute the email address to be converted
	 * @return the string representation of the role name
	 */
	@Override
	public String convertToDatabaseColumn(RoleName attribute) {
		return RoleName.toString(attribute);
	}

	/**
	 * Converts the a string to a role name
	 * Returns <code>null</code> if the string is <code>null</code> or empty.
	 * @param dbData the string value to be converted
	 * @return the specified string as role name
	 */
	@Override
	public RoleName convertToEntityAttribute(String dbData) {
		return RoleName.valueOf(dbData);
	}

}
