/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.service;

import javax.json.bind.annotation.JsonbTypeAdapter;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.users.jsonb.EmailAddressAdapter;

@JsonbTypeAdapter(EmailAddressAdapter.class)
public class EmailAddress extends Scalar<String> {

	private static final long serialVersionUID = 1L;

	public static EmailAddress valueOf(String email) {
		return fromString(email, EmailAddress::new);
	}
	
	private String value;
	
	public EmailAddress(String value) {
		this.value = value;
	}
	
	@Override
	public String getValue() {
		return value;
	}
	
}
