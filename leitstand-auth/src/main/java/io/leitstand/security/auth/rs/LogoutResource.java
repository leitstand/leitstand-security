/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.rs;

import static java.lang.String.format;

import java.util.logging.Logger;

import javax.enterprise.context.RequestScoped;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;

@RequestScoped
@Path("/logout")
public class LogoutResource {
	
	private static final Logger LOG = Logger.getLogger(LogoutResource.class.getName());

	@POST
	public void logout(@Context HttpServletRequest request) {
		try {
			request.logout();
		} catch (ServletException e) {
			LOG.fine(() -> format("An error occured while attempting to logoff user %s: %s", 
								  request.getUserPrincipal(), 
								  e.getMessage()));
		}
	}
	
}
