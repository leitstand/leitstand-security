/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.jpa;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import io.leitstand.security.auth.accesskey.AccessKeyId;


@Converter(autoApply=true)
public class AccessKeyIdConverter implements AttributeConverter<AccessKeyId, String>{

	@Override
	public String convertToDatabaseColumn(AccessKeyId id) {
		return AccessKeyId.toString(id);
	}

	@Override
	public AccessKeyId convertToEntityAttribute(String name) {
		return AccessKeyId.valueOf(name);
	}

}
