/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.jpa;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import io.leitstand.security.users.service.EmailAddress;

/**
 * Converters a {@link EmailAddress} to a string an vice versa.
 */
@Converter
public class EmailAddressConverter implements AttributeConverter<EmailAddress, String>{

	/**
	 * Converts the given email address to a string. 
	 * Returns <code>null</code> if the given email address is <code>null</code>.
	 * @param attribute - the email address to be converted
	 * @return the string representation of the given email address
	 */
	@Override
	public String convertToDatabaseColumn(EmailAddress attribute) {
		return EmailAddress.toString(attribute);
	}

	/**
	 * Converts the specified string to an email address.
	 * Returns <code>null</code> if the string is <code>null</code> or empty.
	 * @param dbData - the string value to be converted
	 * @return the specified string as email address
	 */
	@Override
	public EmailAddress convertToEntityAttribute(String dbData) {
		return EmailAddress.valueOf(dbData);
	}

}
