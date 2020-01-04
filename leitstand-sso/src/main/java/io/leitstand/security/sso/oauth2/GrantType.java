/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.oauth2;

import io.leitstand.commons.model.Scalar;

public class GrantType extends Scalar<String>{

	private static final long serialVersionUID = 1L;

	private String value;
	
	public GrantType(String value) {
		this.value = value;
	}
	
	@Override
	public String getValue() {
		return value;
	}
	
}
