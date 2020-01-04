/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import io.leitstand.security.auth.Authenticated;
import io.leitstand.security.auth.UserId;

@ApplicationScoped
class AuthenticatedUserProvider {

	@Inject
	private HttpServletRequest request;
	
	@Produces
	@RequestScoped
	@Authenticated
	public UserId getAuthenticatedUserId() {
		return UserId.valueOf(request.getUserPrincipal());
	}
	
}