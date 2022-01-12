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
package io.leitstand.security.sso.oidc.rs;

import static io.leitstand.commons.etc.Environment.getSystemProperty;
import static io.leitstand.security.sso.oidc.ReasonCode.OID0003I_SESSION_CREATED;
import static java.lang.String.format;
import static java.net.URLDecoder.decode;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.Response.ok;

import java.io.UnsupportedEncodingException;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;

import io.leitstand.commons.rs.Public;
import io.leitstand.commons.rs.Resource;
import io.leitstand.security.oauth2.Oauth2AccessToken;
import io.leitstand.security.sso.oidc.oauth2.RefreshTokenStore;
import io.leitstand.security.sso.oidc.service.OidcService;
import io.leitstand.security.sso.oidc.service.OidcUserInfo;
import io.leitstand.security.sso.oidc.user.OidcUserService;

@Public
@Resource
@Path("/login/oidc/")
@Consumes(APPLICATION_JSON)
@Produces(APPLICATION_JSON)
public class OidcAuthenticationFlowResource {
	
	private static final String ID_COOKIE  = getSystemProperty("LEITSTAND_ID_TOKEN","LEITSTAND_ID");
	private static final String JWS_COOKIE = getSystemProperty("LEITSTAND_ACCESS_TOKEN_COOKIE_NAME","LEITSTAND_ACCESS");
	
	private static final Logger LOG = Logger.getLogger(OidcAuthenticationFlowResource.class.getName());

	@Inject
	private OidcService oidc;
	
	@Inject
	private OidcUserService users;
	
	@Inject
	private RefreshTokenStore refreshTokens;
	
	@POST
	@Path("/_authentication_flow")
	public Response authenticate(@QueryParam("code") String code, 
								 @QueryParam("redirect_uri") String redirectUri) throws UnsupportedEncodingException{
		
		// Obtain an access token
		Oauth2AccessToken accessToken = oidc.getAccessToken(code, decode(redirectUri,"UTF-8"));
	
		
		// Load user info
		OidcUserInfo userInfo = oidc.getUserInfo(accessToken);
		
		// Store user for auditing
		users.storeUser(userInfo);
		
		// Store refresh token.
		refreshTokens.storeRefreshToken(userInfo.getSub(),
										 accessToken.getRefreshToken());
		
		LOG.fine(() -> format("%s: Created session for user %s",
							  OID0003I_SESSION_CREATED.getReasonCode(),
							  userInfo.getUserName()));

		return ok(userInfo)
			   .cookie(cookie(ID_COOKIE,
					   		  accessToken.getIdToken(),
					   		  accessToken.getRefreshExpiresIn()))
			   .cookie(cookie(JWS_COOKIE,
					   		  accessToken.getAccessToken(),
					   		  accessToken.getRefreshExpiresIn()))
			   .build();
		
	}
	
	private NewCookie cookie(String name, String value, int maxAge) {
		return new NewCookie(name,value,"/",null,null,maxAge,false,true);
	}
		
}
