/*
 * Copyright 2020 RtBrick Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
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
