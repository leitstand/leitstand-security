/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.http;

import static io.leitstand.security.auth.UserName.userName;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import io.leitstand.security.auth.Authenticated;
import io.leitstand.security.auth.UserName;

@ApplicationScoped
class AuthenticatedUserProvider {

	@Inject
	private HttpServletRequest request;
	
	@Produces
	@RequestScoped
	@Authenticated
	public UserName getAuthenticatedUserName() {
		return userName(request.getUserPrincipal());
	}
	
}