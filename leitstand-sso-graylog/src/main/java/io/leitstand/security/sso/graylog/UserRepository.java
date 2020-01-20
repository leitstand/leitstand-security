/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.sso.graylog;

import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.sso.graylog.UserInfo.newUserInfo;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;

import io.leitstand.security.auth.UserName;
import io.leitstand.security.users.service.EmailAddress;
import io.leitstand.security.users.service.UserService;
import io.leitstand.security.users.service.UserSettings;

@RequestScoped
@Path("/oauth2/graylog/user")
public class UserRepository {
	
	@Inject
	private UserService users;

	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public UserInfo getUserInfo(@Context SecurityContext context) {
		
		UserSettings user = users.getUser(userName(context.getUserPrincipal()));
		
		return newUserInfo()
			   .withName(user.getGivenName())
			   .withSurname(user.getFamilyName())
			   .withEmail(EmailAddress.toString(user.getEmail()))
			   .withUsername(user.getUserName())
			   .withRoles(user.getRoles())
			   .build();
	}
		
}
