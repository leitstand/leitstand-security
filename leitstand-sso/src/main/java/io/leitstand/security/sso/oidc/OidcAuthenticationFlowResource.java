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

import static io.leitstand.security.sso.oidc.ReasonCode.OID0003I_SESSION_CREATED;
import static java.lang.String.format;
import static java.net.URLDecoder.decode;

import java.io.UnsupportedEncodingException;
import java.util.Set;
import java.util.logging.Logger;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;

import io.leitstand.security.auth.http.CookieManager;
import io.leitstand.security.sso.oauth2.Oauth2AccessToken;

@RequestScoped
@Path("/login/oidc/")
public class OidcAuthenticationFlowResource {
	
	private static final Logger LOG = Logger.getLogger(OidcAuthenticationFlowResource.class.getName());

	@Inject
	private OidcClient oidc;
	
	@Inject
	private CookieManager cookieManager;
	
	@Inject
	private OidcUserService users;
	
	@POST
	@Path("/_authentication_flow")
	public UserInfo authenticate(@Context HttpServletRequest request, 
								 @Context HttpServletResponse response) throws UnsupportedEncodingException{
		
		// Obtain an access token

		Oauth2AccessToken accessToken = oidc.getAccessToken(request.getParameter("code"),
															decode(request.getParameter("redirect_uri"),"UTF-8"));
	
		// Load user info
		UserInfo userInfo = oidc.getUserInfo(accessToken);
		
		// Store user and read the assigned roles.
		Set<String> assignedRoles = users.storeUser(userInfo);
		
		// Issue access token to authenticate subsequent requests
		cookieManager.issueAccessToken(request, 
									   response, 
									   userInfo.getUserName(),
									   assignedRoles);
		LOG.fine(() -> format("%s: Created session for user %s",
							  OID0003I_SESSION_CREATED.getReasonCode(),
							  userInfo.getUserName()));
		
		return userInfo;
	}
		
}
