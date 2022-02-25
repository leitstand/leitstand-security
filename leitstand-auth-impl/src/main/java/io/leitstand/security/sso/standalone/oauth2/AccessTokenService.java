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
package io.leitstand.security.sso.standalone.oauth2;

import static io.leitstand.commons.messages.MessageFactory.createMessage;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.accesskeys.ApiAccessKey.newApiAccessKey;
import static io.leitstand.security.oauth2.Oauth2AccessToken.newOauth2AccessToken;
import static io.leitstand.security.sso.standalone.ReasonCode.OAH0002E_CLIENT_ID_MISMATCH;
import static java.lang.String.format;
import static java.lang.System.currentTimeMillis;
import static java.util.concurrent.TimeUnit.SECONDS;
import static java.util.logging.Logger.getLogger;
import static javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.Response.ok;
import static javax.ws.rs.core.Response.status;
import static javax.ws.rs.core.Response.Status.FORBIDDEN;

import java.util.Date;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.rs.Resource;
import io.leitstand.security.auth.accesskeys.ApiAccessKey;
import io.leitstand.security.auth.accesskeys.ApiAccessKeyEncoder;
import io.leitstand.security.auth.jwt.Claims;
import io.leitstand.security.auth.user.UserRegistry;
import io.leitstand.security.oauth2.Oauth2AccessToken;
import io.leitstand.security.sso.standalone.config.StandaloneLoginConfig;
import io.leitstand.security.users.service.UserInfo;

/**
 * The OAuth authorization server implementation.
 */
@Resource
@Path("/oauth2")
public class AccessTokenService {
	
	private static final Logger LOG = getLogger(AccessTokenService.class.getName());
	
	private static final String OAUTH2_CODE = "code";
	
	@Inject
	private Messages messages;
	
	@Inject
	private UserRegistry users; 
	
	@Inject
	private CodeService codes;
	
	@Inject
	private ApiAccessKeyEncoder encoder;
	
	
	@POST
	@Path("/token")
	@Consumes(APPLICATION_FORM_URLENCODED)
	@Produces(APPLICATION_JSON)
	public Response getAccessToken(@Context SecurityContext context,
								   @FormParam("grant_type") String grantType,
								   @FormParam(OAUTH2_CODE) String code) {
		CodePayload payload = codes.decodeCode(code);
		
		
		if(payload != null && context.getUserPrincipal().getName().equals(payload.getClientId())) {
			
			UserInfo userInfo = users.getUserInfo(userName(payload.getUserName()));
			
			if(userInfo == null) {
				return status(FORBIDDEN).entity(messages).build();
			}
			
			ApiAccessKey token = newApiAccessKey()
								 .withUserName(userInfo.getUserName())
								 .withDateExpiry(new Date(currentTimeMillis()+SECONDS.toMillis(60)))
								 .withTemporaryAccess(true)
								 .build();

			String token64 = encoder.encode(token);
			Oauth2AccessToken oauthToken = newOauth2AccessToken()
								 	  	   .withAccessToken(token64)
								 	  	   .withExpiresIn(5000)
								 	  	   .withTokenType("Bearer")
								 	  	   .build();
			return ok(oauthToken).build();
			
		}
		
		LOG.warning(() -> format("%s: Request for access token rejected due invalid client ID",
						         OAH0002E_CLIENT_ID_MISMATCH.getReasonCode()));
		messages.add(createMessage(OAH0002E_CLIENT_ID_MISMATCH, 
								   context.getUserPrincipal().getName()));
		return status(FORBIDDEN).entity(messages).build();
	}
	
}
