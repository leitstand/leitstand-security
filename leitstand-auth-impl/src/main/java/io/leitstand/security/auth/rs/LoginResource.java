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
package io.leitstand.security.auth.rs;

import static io.leitstand.security.auth.UserName.userName;
import static java.lang.String.format;
import static java.util.logging.Logger.getLogger;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import java.util.logging.Logger;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import io.leitstand.commons.rs.Public;
import io.leitstand.commons.rs.Resource;
import io.leitstand.security.auth.user.UserRegistry;
import io.leitstand.security.users.service.UserInfo;

@Public
@Resource
@Consumes(APPLICATION_JSON)
@Produces(APPLICATION_JSON)
@Path("")
public class LoginResource {
	
	private static final Logger LOG = getLogger(LoginResource.class.getName());

	@Inject
	private UserRegistry users;
	
	@POST
	@Path("/login")
	public UserInfo login(@Context SecurityContext context) {
		return users.getUserInfo(userName(context.getUserPrincipal()));
	}
	
	@GET
	@Path("/logout")
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
