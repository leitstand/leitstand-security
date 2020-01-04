/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.jpa;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import io.leitstand.security.auth.UserId;

@Converter(autoApply=true)
public class UserIdConverter implements AttributeConverter<UserId, String>{

	@Override
	public String convertToDatabaseColumn(UserId userId) {
		return UserId.toString(userId);
	}

	@Override
	public UserId convertToEntityAttribute(String userId) {
		return UserId.valueOf(userId);
	}
	
}
