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

import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.security.sso.standalone.ReasonCode.OAH0001E_UNSUPPORTED_RESPONSE_TYPE;
import static java.lang.String.format;
import static java.util.logging.Logger.getLogger;
import static javax.ws.rs.core.Response.temporaryRedirect;

import java.io.IOException;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import io.leitstand.commons.rs.Public;
import io.leitstand.commons.rs.Resource;

/**
 * The OAuth authorization server implementation.
 */
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
	
	private CodeService codes;
	
	public AuthorizationService() {
		// CDI and JAX-RS
	}
	
	@Inject
	protected AuthorizationService(CodeService codes) {
		this.codes = codes;
	}
	
	/**
	 * Creates an authorization code to authorize the authenticated user to access the specified resource and eventually redirects the user to the resource.
	 * @param context the security context to determine the authenticated user
	 * @param scope the optional scope parameter, to restrict the access to a certain scope (see OAuth <code>scope</code> specification)
	 * @param responseType the requested response type. Only <code>code</code> is supported as of now. Other values cause an exception (see OAuth <code>response_type</code> specification)
	 * @param clientId the client for which the authentication code was requested (see OAuth <code>client_id</code> specification)
	 * @param redirectUri the URI of the target resource (see OAuth <code>redirect_uri</code> specification)
	 * @param state the optional state parameter (see OAuth <code>state</code> specification)
	 * @return a <code>302 temporary redirect</code> to the specified redirect URI with an appropriate authorization code or a <code>400 bad request</code> if the client did not request an authorization code.
	 * @throws IOException if an IO error occurs
	 */
	@Public
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
			
		    String code = codes.createCode(clientId, 
		    							   context.getUserPrincipal().getName());
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
		
}
