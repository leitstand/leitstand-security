package io.leitstand.security.sys.rs;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import com.nimbusds.jose.jwk.JWKSet;

import io.leitstand.commons.rs.Public;
import io.leitstand.commons.rs.Resource;
import io.leitstand.security.sys.service.SsoSettings;
import io.leitstand.security.sys.service.SsoSettingsService;

/**
 * REST resource for reading the Single-Sign On settings.
 * @see SsoSettings
 * @see SsoSettingsService
 */
@Resource
@Public // Allow unauthenticated access. A Leitstand service reads this information to validate access tokens!
@Path("/auth/config")
@Produces(APPLICATION_JSON)
public class SsoSettingsResource {

    
    private SsoSettingsService service;
    
    public SsoSettingsResource() {
		// CDI and JAX-RS
    }
    
    @Inject
    protected SsoSettingsResource(SsoSettingsService service) {
    	this.service = service;
    }
    
    /**
     * Returns the Single-Sign On settings enabling other Leitstand services to 
     * validate Leitstand access tokens.
     * @return the Single-Sign On settings.
     */
    @GET
    public SsoSettings getSsoSettings() {
        return service.getSsoSettings();
    }

    
    /**
     * Returns the JSON Web Key Set to validate Leitstand access tokens.
     * @return the JSON Web Key Set to validate Leitstand access tokens.
     */
    @GET
    @Path("/jwks")
    public JWKSet getJWKSet() {
        return service.getJWKSet();
    }
    
}
