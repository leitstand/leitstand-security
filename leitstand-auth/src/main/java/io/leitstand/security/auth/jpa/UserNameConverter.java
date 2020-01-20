/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.jpa;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import io.leitstand.security.auth.UserName;

@Converter(autoApply=true)
public class UserNameConverter implements AttributeConverter<UserName, String>{

	@Override
	public String convertToDatabaseColumn(UserName userName) {
		return UserName.toString(userName);
	}

	@Override
	public UserName convertToEntityAttribute(String userName) {
		return UserName.valueOf(userName);
	}
	
}
