/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;

import static io.leitstand.commons.model.StringUtil.isNonEmptyString;

import javax.servlet.http.HttpServletRequest;

import io.leitstand.commons.model.CompositeValue;

/**
 * A utility class to process the HTTP <code>Authorization</code> header.
 * <p>
 * Use {@link #valueOf(String)} to obtain a <code>Authorization</code> instance.
 */
public class Authorization extends CompositeValue {

	public static final String HTTP_AUTHORIZATION_HEADER = "Authorization";
	
	public static Authorization valueOf(HttpServletRequest request) {
		return valueOf(request.getHeader(HTTP_AUTHORIZATION_HEADER));
	}
	
	/**
	 * Creates an <code>Authorization</code> instance from the specified string. 
	 * Returns <code>null</code> if the specified string is <code>null</code> or empty.
	 * @param header - the <i>Authorization</i> HTTP header
	 * @return the <code>Authorization</code> header or <code>null</code> if the <i>Authorization</i> HTTP header is <code>null</code> or empty.
	 */
	public static Authorization valueOf(String header) {
		if(isNonEmptyString(header)) {
			return new Authorization(header);
		}
		return null;
	}
	
	private String credentials;
	private String type;
	
	/**
	 * Creates a <code>Authorization</code> header.
	 * @param header the Authorization HTTP header value
	 */
	public Authorization(String header) {
		String[] segments = header.split(" ");
		this.type = segments[0];
		this.credentials = segments[1];
	}
	
	/**
	 * Returns <code>true</code> if the HTTP <i>Authorization</i> header conveys a bearer token.
	 * @return <code>true</code> if the HTTP <i>Authorization</i> header conveys a bearer token.
	 */
	public boolean isBearerToken() {
		return "Bearer".equalsIgnoreCase(type);
	}

	/**
	 * Returns <code>true</code> if the HTTP <i>Authorization</i> header conveys HTTP basic authentication data.
	 * @return <code>true</code> if the HTTP <i>Authorization</i> header conveys HTTP basic authentication data.
	 */
	public boolean isBasic() {
		return "Basic".equalsIgnoreCase(type);
	}

	/**
	 * Returns the credentials to be verified for authentication.
	 * @return the credentials to be verified for authentication.
	 */
	public String getCredentials() {
		return credentials;
	}

}