package io.leitstand.security.sso.oidc.config;

import io.leitstand.commons.LeitstandException;
import io.leitstand.security.sso.oidc.ReasonCode;

public class OidcConfigException extends LeitstandException{

    private static final long serialVersionUID = 1L;

    public OidcConfigException(Exception cause, ReasonCode reason, Object... args) {
        super(cause,reason,args);
    }
    
}
