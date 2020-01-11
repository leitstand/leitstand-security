/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;

import static io.leitstand.commons.model.StringUtil.fromUtf8Bytes;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;

import javax.security.enterprise.credential.Password;

import io.leitstand.commons.model.CompositeValue;
import io.leitstand.security.auth.UserName;

/**
 * A helper to handle HTTP Basic authentication data.
 */
public class BasicAuthentication extends CompositeValue{


	/**
	 * Creates a <code>BasicAuthentication</code> instance from the specified <code>Authorization</code> header.
	 * @param header - the HTTP <i>Authorization</i> header
	 * @return the <code>BasicAuthentication</code> instance, unless the specified <code>Authorization</code> header is <code>null</code> or did not convey HTTP Basic Authentication data.
	 * @throws IllegalArgumentException if the <i>Authorization</i> HTTP header does not convey HTTP Basic authentication data.
	 */
	public static BasicAuthentication valueOf(Authorization header) {
		if(header == null) {
			return null;
		}
		return new BasicAuthentication(header);
	}
	
	public static BasicAuthentication basicAuthentication(UserName userName, Password password) {
		return new BasicAuthentication(userName,password);
	}
	
	private UserName userName;
	private Password password;
	
	public BasicAuthentication(UserName userName, Password password) {
		this.userName = userName;
		this.password = password;
	}
	
	/**
	 * Creates a <code>BasicAuthentication</code> helper using UTF-8 to decode the HTTP Basic Authentication data.
	 * @param header the HTTP Authorization header.
	 * @throws IllegalArgumentException if the header does not convey HTTP Basic Authentication data
	 */
	public BasicAuthentication(Authorization header) {
		if(!header.isBasic()) {
			throw new IllegalArgumentException("Basic authorization header expected!");
		}
		String credentials = fromUtf8Bytes(getDecoder().decode(header.getCredentials()));
		this.userName = new UserName(credentials.substring(0, credentials.indexOf(':')));
		this.password = new Password(credentials.substring(userName.length()+1));
	}
	
	/**
	 * Returns the provided user name.
	 * @return the provided user name.
	 */
	public UserName getUserName() {
		return userName;
	}
	
	/**
	 * Returns the provided password.
	 * @return the provided password.
	 */
	public Password getPassword() {
		return password;
	}
	
	@Override
	public String toString() {
		String credentials = userName+":"+new String(password.getValue());
		return "Basic "+getEncoder().encodeToString(toUtf8Bytes(credentials));
	}

}
