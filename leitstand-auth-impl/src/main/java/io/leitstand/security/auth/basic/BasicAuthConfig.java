package io.leitstand.security.auth.basic;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static java.lang.Boolean.parseBoolean;

import javax.enterprise.context.Dependent;

/**
 * HTTP Basic Authentication configuration.
 */
@Dependent
class BasicAuthConfig {

    private static final boolean BASIC_AUTH_ENABLED = parseBoolean(getSystemProperty("BASIC_AUTH_ENABLED","false"));


    
    /**
     * Returns whether HTTP Basic Authentication support is enabled or not.
     * @return <code>true</code> if HTTP Basic Authentication support is enabled, <code>false</code> otherwise.
     */
    public boolean isBasicAuthEnabled() {
        return BASIC_AUTH_ENABLED;
    }
    
    
}
