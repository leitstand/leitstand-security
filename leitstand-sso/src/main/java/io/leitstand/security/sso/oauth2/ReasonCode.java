/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.oauth2;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.ResourceBundle;

import io.leitstand.commons.Reason;

/**
 * Enumeration of OAuth reason codes.
 */
public enum ReasonCode implements Reason{
	OAH0001E_UNSUPPORTED_RESPONSE_TYPE,
	OAH0002E_CLIENT_ID_MISMATCH;
	
	private static final ResourceBundle MESSAGES = ResourceBundle.getBundle("Oauth2Messages");

	
	/**
	 * {@inheritDoc}
	 */
	public String getMessage(Object... args){
		try{
			String pattern = MESSAGES.getString(name());
			return MessageFormat.format(pattern, args);
		} catch(Exception e){
			return name() + Arrays.asList(args);
		}
	}
}
