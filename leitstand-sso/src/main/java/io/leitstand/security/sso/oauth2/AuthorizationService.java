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
package io.leitstand.security.sso.oauth2;

import static io.leitstand.commons.messages.MessageFactory.createMessage;
import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.auth.accesskey.ApiAccessKey.newApiAccessKey;
import static io.leitstand.security.sso.oauth2.Oauth2AccessToken.newOauth2AccessToken;
import static io.leitstand.security.sso.oauth2.ReasonCode.OAH0001E_UNSUPPORTED_RESPONSE_TYPE;
import static io.leitstand.security.sso.oauth2.ReasonCode.OAH0002E_CLIENT_ID_MISMATCH;
import static java.lang.String.format;
import static java.lang.System.currentTimeMillis;
import static java.util.concurrent.TimeUnit.SECONDS;
import static java.util.logging.Logger.getLogger;
import static javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.Response.ok;
import static javax.ws.rs.core.Response.status;
import static javax.ws.rs.core.Response.temporaryRedirect;
import static javax.ws.rs.core.Response.Status.FORBIDDEN;

import java.io.IOException;
import java.util.Date;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.leitstand.commons.messages.Messages;
import io.leitstand.commons.rs.Public;
import io.leitstand.commons.rs.Resource;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.accesskey.ApiAccessKeyEncoder;
import io.leitstand.security.auth.standalone.StandaloneLoginConfig;
import io.leitstand.security.auth.user.UserInfo;
import io.leitstand.security.auth.user.UserRegistry;

/**
 * The OAuth authorization server implementation.
 */
@Public
@Resource
@Path("/oauth2")
public class AuthorizationService {
	
	private static final Logger LOG = getLogger(AuthorizationService.class.getName());
	
	private static final String OAUTH2_SCOPE = "scope";
	private static final String OAUTH2_RESPONSE_TYPE = "response_type";
	private static final String OAUTH2_CLIENT_ID = "client_id";
	private static final String OAUTH2_REDIRECT_URI = "redirect_uri";
	private static final String OAUTH2_STATE = "state";
	private static final String OAUTH2_CODE = "code";
	private static final String OAUTH2_ERROR = "error";
	private static final String OAUTH2_ERROR_UNAUTHENTICATED = "unauthenticated";
	private static final String OAUTH2_ERROR_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
	
	@Inject
	private Messages messages;
	
	@Inject
	private UserRegistry users; 
	
	@Inject
	private StandaloneLoginConfig config;
	
	@Inject
	private ApiAccessKeyEncoder encoder;
	
	

	
	/**
	 * Creates an authorization code to authorize the authenticated user to access the specified resource and eventually redirects the user to the resource.
	 * @param context the security context to determine the authenticated user
	 * @param scope the optional scope parameter, to restrict the access to a certain scope (see OAuth <code>scope</code> specification)
	 * @param responseType the requested response type. Only <code>code</code> is supported as of now. Other values cause an exception (see OAuth <code>response_type</code> specification)
	 * @param clientId the client for which the authentication code was requested (see OAuth <code>client_id</code> specification)
	 * @param redirectUri the URI of the target resource (see OAuth <code>redirect_uri</code> specification)
	 * @param state the optional state parameter (see OAuth <code>state</code> specification)
	 * @return a <code>302 temporary redirect</code> to the specified redirect URI with an appropriate authorization code or a <code>400 bad request</code> if the client did not request an authorization code.
	 * @throws IOException
	 */
	@Path("/authorize")
	@GET
	public Response authorize(@Context SecurityContext context,
							  @QueryParam(OAUTH2_SCOPE) String scope,
							  @QueryParam(OAUTH2_RESPONSE_TYPE) String responseType,
							  @QueryParam(OAUTH2_CLIENT_ID) String clientId,
							  @QueryParam(OAUTH2_REDIRECT_URI) String redirectUri,
							  @QueryParam(OAUTH2_STATE) String state) throws IOException {

		UriBuilder target = new UriBuilder(redirectUri);
		
		if(unauthenticated(context)) {
			target.addQueryParam(OAUTH2_ERROR, OAUTH2_ERROR_UNAUTHENTICATED);
			if(isNonEmptyString(state)) {
				target.addQueryParam(OAUTH2_STATE,state);
			}
			return temporaryRedirect(target.toUri())
				   .build();
		}
		
		if(OAUTH2_CODE.equals(responseType)){
			
			String code = config.signAccessToken(Jwts.builder()
										  	         .setSubject(context.getUserPrincipal().getName())
										  	         .setAudience(clientId)
										  	         .setIssuedAt(new Date()));

			target.addQueryParam(OAUTH2_CODE,code);
			if(isNonEmptyString(state)) {
				target.addQueryParam(OAUTH2_STATE,state);
			}
			return temporaryRedirect(target.toUri())
				   .build();
		}
		LOG.fine(() -> format("%s: Invalid response_type parameter %s. Parameter must be set to code as stated by OAuth specification.",
							  OAH0001E_UNSUPPORTED_RESPONSE_TYPE.getReasonCode(),
							  responseType));
		
		// OAuth specifies the error response as redirect with error parameter.
		// Consequently messages must not be used, because a redirect must not have an entity.
		target.addQueryParam(OAUTH2_ERROR,OAUTH2_ERROR_UNSUPPORTED_RESPONSE_TYPE);
		if(isNonEmptyString(state)) {
			target.addQueryParam(OAUTH2_STATE,state);
		}
		return temporaryRedirect(target.toUri())
			   .build();
	}
	
	private boolean unauthenticated(SecurityContext context) {
		return context.getUserPrincipal() == null;
	}
	
	@POST
	@Path("/token")
	@Consumes(APPLICATION_FORM_URLENCODED)
	@Produces(APPLICATION_JSON)
	public Response getAccessToken(@Context SecurityContext context,
								   @FormParam("grant_type") String grantType,
								   @FormParam(OAUTH2_CODE) String code) {
		
		Jws<Claims> jws = config.decodeAccessToken(code);
		
		
		if(context.getUserPrincipal().getName().equals(jws.getBody().getAudience())) {
			
			UserInfo userInfo = users.getUserInfo(userName(jws.getBody().getSubject()));
			
			if(userInfo == null) {
				return status(FORBIDDEN).entity(messages).build();
			}
			
			ApiAccessKey token = newApiAccessKey()
								 .withUserName(userInfo.getUserName())
								 .withDateExpiry(new Date(currentTimeMillis()+SECONDS.toMillis(60)))
								 .build();

			String token64 = encoder.encode(token);
			Oauth2AccessToken oauthToken = newOauth2AccessToken()
								 	  	   .withAccessToken(token64)
								 	  	   .withExpiresIn(5000)
								 	  	   .withTokenType("Bearer")
								 	  	   .build();
			return ok(oauthToken).build();
			
		}
		
		LOG.warning(() -> format("%s: Request for access token rejected due invalid client ID.",
						         OAH0002E_CLIENT_ID_MISMATCH.getReasonCode()));
		LOG.fine(() -> format("client_id parameter (%s) does not match expected value (%s)",
							  context.getUserPrincipal().getName(),
							  jws.getBody().getAudience()));
		messages.add(createMessage(OAH0002E_CLIENT_ID_MISMATCH, 
								   context.getUserPrincipal().getName()));
		return status(FORBIDDEN).entity(messages).build();
	}
	
}
