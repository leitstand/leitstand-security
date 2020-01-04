/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.rs;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import io.leitstand.security.auth.UserId;
import io.leitstand.security.auth.user.UserInfo;
import io.leitstand.security.auth.user.UserRegistry;

@RequestScoped
@Path("/_login")
public class LoginResource {

	@Inject
	private UserRegistry users;
	
	@POST
	public UserInfo login(@Context SecurityContext context) {
		return users.getUserInfo(UserId.valueOf(context.getUserPrincipal()));
	}
	
}
