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
