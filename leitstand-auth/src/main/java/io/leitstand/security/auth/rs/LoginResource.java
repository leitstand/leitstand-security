/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.rs;

import static io.leitstand.security.auth.UserName.userName;
import static java.lang.String.format;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import java.util.logging.Logger;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import io.leitstand.security.auth.http.LoginConfiguration;
import io.leitstand.security.auth.user.UserInfo;
import io.leitstand.security.auth.user.UserRegistry;

@RequestScoped
@Path("/login")
@Consumes(APPLICATION_JSON)
@Produces(APPLICATION_JSON)
public class LoginResource {
	
	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

	@Inject
	private UserRegistry users;
	
	@Inject
	private LoginConfiguration loginConfig;
	
	@POST
	@Path("/_login")
	public UserInfo login(@Context SecurityContext context) {
		return users.getUserInfo(userName(context.getUserPrincipal()));
	}
	
	@POST
	@Path("/_logout")
	public void logout(@Context HttpServletRequest request) {
		try {
			request.logout();
		} catch (ServletException e) {
			LOG.fine(() -> format("An error occured while attempting to logoff user %s: %s", 
								  request.getUserPrincipal(), 
								  e.getMessage()));
		}
	}
	
	@GET
	@Path("/config")
	public LoginConfiguration getLoginConfiguration() {
		return loginConfig;
	}
	
}
