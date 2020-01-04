/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.openid;

import static io.leitstand.security.sso.openid.UserInfo.newUserInfo;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import io.leitstand.security.auth.UserId;
import io.leitstand.security.users.service.UserService;
import io.leitstand.security.users.service.UserSettings;

@RequestScoped
@Path("/oauth2/openid")
public class UserInfoResource {

	@Inject
	private UserService users;
	
	@GET
	@Produces(APPLICATION_JSON)
	public UserInfo getUserInfo(@Context SecurityContext context) {
		
		UserSettings user = users.getUser(UserId.valueOf(context.getUserPrincipal()));
		
		return newUserInfo()
			   .withSub(user.getUserId())
			   .withName(user.getGivenName()+" "+user.getSurname())
			   .withEmail(user.getEmail())
			   .build();
	}
		
}
