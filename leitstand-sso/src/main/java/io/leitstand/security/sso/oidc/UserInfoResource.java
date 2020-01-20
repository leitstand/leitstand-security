/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.oidc;

import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.sso.oidc.UserInfo.newUserInfo;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import io.leitstand.security.users.service.UserService;
import io.leitstand.security.users.service.UserSettings;

@RequestScoped
@Path("/oidc/userinfo")
public class UserInfoResource {

	@Inject
	private UserService users;
	
	@GET
	@Produces(APPLICATION_JSON)
	public UserInfo getUserInfo(@Context SecurityContext context) {
		
		UserSettings user = users.getUser(userName(context.getUserPrincipal()));
		
		return newUserInfo()
			   .withSub(user.getUserId().toString())
			   .withGivenName(user.getGivenName())
			   .withFamilyName(user.getFamilyName())
			   .withName(user.getGivenName()+" "+user.getFamilyName())
			   .withPreferredUsername(user.getUserName().toString())
			   .withEmail(user.getEmail())
			   .build();
	}
		
}
