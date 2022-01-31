package io.leitstand.security.sso.sys.rs;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import io.leitstand.commons.rs.Public;
import io.leitstand.commons.rs.Resource;
import io.leitstand.security.sso.sys.service.LoginConfiguration;
import io.leitstand.security.sso.sys.service.LoginConfigurationService;

/**
 * REST resource to read the login configuration.
 * @see LoginConfiguration
 */
@Resource
@Public // Allow unauthenticated access, because login configuration is required to know how to establish a session. 
@Path("/login/config")
@Produces(APPLICATION_JSON)
public class LoginConfigResource {

	@Inject
	private LoginConfigurationService service;
	
	/**
	 * Returns the active login configuration.
	 * @return the active login configuration.
	 */
	@GET
	public LoginConfiguration getLoginConfiguration() {
		return service.getLoginConfiguration();
	}
}
