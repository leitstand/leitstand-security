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
package io.leitstand.security.sso.standalone.rs;

import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.sso.oidc.service.OidcUserInfo.newUserInfo;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import io.leitstand.commons.rs.Resource;
import io.leitstand.security.sso.oidc.service.OidcUserInfo;
import io.leitstand.security.users.service.UserService;
import io.leitstand.security.users.service.UserSettings;

@Resource
@Path("/oidc/userinfo")
@Consumes(APPLICATION_JSON)
@Produces(APPLICATION_JSON)
public class UserInfoResource {

	private UserService users;
	
	protected UserInfoResource() {
		// CDI
	}
	
	@Inject
	protected UserInfoResource(UserService users) {
		this.users = users;
	}
	
	@GET
	public OidcUserInfo getUserInfo(@Context SecurityContext context) {
		
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
