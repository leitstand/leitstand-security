/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.service;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.ResourceBundle;

import io.leitstand.commons.Reason;

public enum ReasonCode implements Reason{
	
	AKY0001E_ACCESS_KEY_NOT_FOUND,
	AKY0002I_ACCESS_KEY_CREATED,
	AKY0003I_ACCESS_KEY_REMOVED,
	AKY0004I_ACCESS_METADATA_UPDATED, 
	AKY0005E_DUPLICATE_KEY_NAME, 
	AKY0006E_DATABASE_ERROR;
	
	private static final ResourceBundle MESSAGES = ResourceBundle.getBundle("AccesskeyMessages");
	
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
