package io.leitstand.security.sys.service;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * Provides access to the Single-Sign On settings.
 */
public interface SsoSettingsService {
    
    /**
     * Returns the Single-Sign On settings.
     * @return the Single-Sign On settings.
     */
    SsoSettings getSsoSettings();
    
    
    /**
     * Returns the JWKS file used for validating an access token.
     * @return the JWKS settings
     */
    JWKSet getJWKSet();
    
    
}
