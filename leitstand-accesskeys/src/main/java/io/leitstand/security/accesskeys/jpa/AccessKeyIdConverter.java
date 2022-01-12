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
package io.leitstand.security.accesskeys.jpa;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.auth.accesskeys.AccessKeyId;


/**
 * <code>AccessKeyId</code> JPA converter.
 */
@Converter(autoApply=true)
public class AccessKeyIdConverter implements AttributeConverter<AccessKeyId, String>{

	/**
	 * Converts an <code>AccessKeyId</code> to a string.
	 * @param id the access key ID
	 * @return access key ID string representation or <code>null</code> if the given access key is <code>null</code>
	 */
	@Override
	public String convertToDatabaseColumn(AccessKeyId id) {
		return Scalar.toString(id);
	}

	/**
	 * Creates an <code>AccessKeyId</code> from the given string.
	 * @param key the string representation of an access key.
	 * @return the <code>AccessKeyId</code> object or <code>null</code> if the given string is <code>null</code> or empty.
	 */
	@Override
	public AccessKeyId convertToEntityAttribute(String key) {
		return AccessKeyId.valueOf(key);
	}

}
