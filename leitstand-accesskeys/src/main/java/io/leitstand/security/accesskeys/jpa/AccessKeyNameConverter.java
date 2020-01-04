/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.jpa;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import io.leitstand.security.accesskeys.service.AccessKeyName;


@Converter(autoApply=true)
public class AccessKeyNameConverter implements AttributeConverter<AccessKeyName, String>{

	@Override
	public String convertToDatabaseColumn(AccessKeyName id) {
		return AccessKeyName.toString(id);
	}

	@Override
	public AccessKeyName convertToEntityAttribute(String id) {
		return AccessKeyName.valueOf(id);
	}

}
