/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;

import io.leitstand.commons.model.Scalar;

/**
 * A helper to handle bearer token data.
 */
public class BearerToken extends Scalar<String>{


	private static final long serialVersionUID = 1L;

	/**
	 * Creates a <code>BasicAuthentication</code> instance from the specified <code>Authorization</code> header.
	 * @param header the HTTP <i>Authorization</i> header
	 * @return the <code>BasicAuthentication</code> instance, unless the specified <code>Authorization</code> header is <code>null</code> or did not convey HTTP Basic Authentication data.
	 * @throws IllegalArgumentException if the <i>Authorization</i> HTTP header does not convey HTTP Basic authentication data.
	 */
	public static BearerToken valueOf(Authorization header) {
		if(header == null) {
			return null;
		}
		return new BearerToken(header);
	}
	
	public static BearerToken bearerToken(String token) {
		return fromString(token,BearerToken::new);
	}
	
	private String value;
	
	public BearerToken(String token) {
		this.value = token;
	}
	
	/**
	 * Creates a <code>BearerToken</code> helper
	 * @param header the HTTP Authorization header.
	 * @throws IllegalArgumentException if the header does not convey HTTP Basic Authentication data
	 */
	public BearerToken(Authorization header) {
		if(!header.isBearerToken()) {
			throw new IllegalArgumentException("Bearer token authorization header expected!");
		}
		this.value = header.getCredentials();
	}
	
	@Override
	public String getValue() {
		return value;
	}
	
	@Override
	public String toString() {
		return "Bearer "+value;
	}

}
