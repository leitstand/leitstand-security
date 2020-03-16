package io.leitstand.security.sso.oidc;

import io.leitstand.commons.LeitstandException;
import io.leitstand.commons.Reason;

public class OidcConfigException extends LeitstandException{

	private static final long serialVersionUID = 1L;
	
	public OidcConfigException(Exception rootCause, Reason reason, Object... arguments) {
		super(rootCause, reason, arguments);
	}
	
	public OidcConfigException(Reason reason, Object... arguments) {
		super(reason, arguments);
	}


}
