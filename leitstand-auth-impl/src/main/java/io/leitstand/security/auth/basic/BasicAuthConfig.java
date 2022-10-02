package io.leitstand.security.auth.basic;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static java.lang.Boolean.parseBoolean;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;

import io.leitstand.security.sso.oidc.config.OidcConfig;

/**
 * HTTP Basic Authentication configuration.
 */
@Dependent
class BasicAuthConfig {

    private static final boolean BASIC_AUTH_ENABLED = parseBoolean(getSystemProperty("BASIC_AUTH_ENABLED","false"));


    @Inject
    private OidcConfig oidcConfig;
    
    
    /**
     * Returns whether HTTP Basic Authentication support is enabled or not.
     * @return <code>true</code> if HTTP Basic Authentication support is enabled, <code>false</code> otherwise.
     */
    public boolean isBasicAuthEnabled() {
        // In case no OpenID/Connect server is configured,
    	// RBMS becomes the authorization server to spawn a SSO domain over RBMS and grafana.
    	// Grafana uses basic authentication - as specified by Oauth - to authenticate the call 
    	// for an access token which is part of the OAuth authorization flow.
    	return BASIC_AUTH_ENABLED || oidcConfig == null;
    }
    
    
}
