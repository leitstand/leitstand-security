/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.service;

import javax.json.bind.annotation.JsonbTypeAdapter;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import io.leitstand.commons.model.Scalar;
import io.leitstand.security.accesskeys.jsonb.AccessKeyNameAdapter;

@JsonbTypeAdapter(AccessKeyNameAdapter.class)
public class AccessKeyName extends Scalar<String>{

	private static final long serialVersionUID = 1L;

	public static AccessKeyName valueOf(String name) {
		return fromString(name,AccessKeyName::new);
	}
	
	public static AccessKeyName valueOf(Scalar<String> name) {
		return valueOf(name.toString());
	}
	
	
	@NotNull(message="{key_name.required}")
	@Pattern(message="{key_name.invalid}", regexp="\\p{Print}{1,64}")
	private String value;
	
	public AccessKeyName(String value) {
		this.value = value;
	}
	
	@Override
	public  String getValue() {
		return value;
	}


	
}
