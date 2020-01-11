package io.leitstand.security.sso.oidc;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.ResourceBundle;

import io.leitstand.commons.Reason;

public enum ReasonCode implements Reason{

	OID0001E_CANNOT_CREATE_ACCESS_TOKEN,
	OID0002E_CANNOT_READ_USER_INFO,
	OID0003I_SESSION_CREATED;
	
	private static final ResourceBundle MESSAGES = ResourceBundle.getBundle("OidcMessages");
	
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