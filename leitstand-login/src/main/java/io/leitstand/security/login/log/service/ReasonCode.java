/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.login.log.service;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.ResourceBundle;

import io.leitstand.commons.Reason;

/**
 * Enumeration of authentication module reason codes.
 */
public enum ReasonCode implements Reason{
	
	/** Login audit log record not found.*/
	AUT0001E_RECORD_NOT_FOUND;
	
	private static final ResourceBundle MESSAGES = ResourceBundle.getBundle("AuditLogMessages");
	
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