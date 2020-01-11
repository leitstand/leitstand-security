/*
 * (c) RtBrick, Inc All rights reserved, 2015 2019
 */
package io.leitstand.security.sso.oauth2;

import static io.leitstand.commons.messages.MessageFactory.createMessage;
import static io.leitstand.commons.model.StringUtil.isNonEmptyString;
import static io.leitstand.security.auth.accesskey.ApiAccessKey.newApiAccessKey;
import static io.leitstand.security.sso.oauth2.AuthorizationCode.newAuthorizationCode;
import static io.leitstand.security.sso.oauth2.Oauth2AccessToken.newOauth2AccessToken;
import static io.leitstand.security.sso.oauth2.ReasonCode.OAH0001E_UNSUPPORTED_RESPONSE_TYPE;
import static io.leitstand.security.sso.oauth2.ReasonCode.OAH0002E_CLIENT_ID_MISMATCH;
import static java.lang.String.format;
import static java.util.logging.Logger.getLogger;
import static javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.Response.ok;
import static javax.ws.rs.core.Response.status;
import static javax.ws.rs.core.Response.temporaryRedirect;
import static javax.ws.rs.core.Response.Status.FORBIDDEN;

import java.io.IOException;
import java.util.logging.Logger;

import javax.enterprise.context.RequestScoped;
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

import io.leitstand.commons.messages.Messages;
import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.jwt.JsonWebTokenDecoder;
import io.leitstand.security.auth.jwt.JsonWebTokenEncoder;
import io.leitstand.security.auth.user.UserInfo;
import io.leitstand.security.auth.user.UserRegistry;

/**
 * The OAuth authorization server implementation.
 */
@RequestScoped
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
	
	private JsonWebTokenEncoder encoder;
	
	private JsonWebTokenDecoder decoder;
	
	private Messages messages;
	
	private UserRegistry users; 
	
	/**
	 * No-argument constructor to create CDI proxy instances.
	 */
	public AuthorizationService() {
		// JPA Constructor
	}
	
	/**
	 * Create a <code>AuthorizationServicey</code>.
	 * @param encoder the JWT encoder
	 * @param decoder the JWT decoder
	 * @param messages the status and error messages container
	 */
	@Inject
	public AuthorizationService(JsonWebTokenEncoder encoder, 
							 	JsonWebTokenDecoder decoder, 
							 	UserRegistry users,
								Messages messages) {
		this.encoder = encoder;
		this.decoder = decoder;
		this.messages = messages;
		this.users = users;
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
			String code64 = encoder.encode(newAuthorizationCode()
										   .withClientId(clientId)
										   .withUserName(new UserName(context.getUserPrincipal().getName()))
										   .build());
			


			target.addQueryParam(OAUTH2_CODE,code64);
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
								   @FormParam("grant_type") GrantType grantType,
								   @FormParam(OAUTH2_CODE) String code) {
		
		AuthorizationCode authCode = decoder.decode(AuthorizationCode.class, 
													AuthorizationCode.Payload.class, 
													code);
		
		
		if(context.getUserPrincipal().getName().equals(authCode.getClientId())) {
			
			UserInfo userInfo = users.getUserInfo(authCode.getUserName());
			
			if(userInfo == null) {
				return status(FORBIDDEN).entity(messages).build();
			}
			
			ApiAccessKey token = newApiAccessKey()
								 .withUserName(userInfo.getUserName())
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
		
		LOG.warning(() -> format("%s: Request for access token rejected due invalid client ID.",
						         OAH0002E_CLIENT_ID_MISMATCH.getReasonCode()));
		LOG.fine(() -> format("client_id parameter (%s) does not match expected value (%s)",
							  context.getUserPrincipal().getName(),
							  authCode.getClientId()));
		messages.add(createMessage(OAH0002E_CLIENT_ID_MISMATCH, 
								   context.getUserPrincipal().getName()));
		return status(FORBIDDEN).entity(messages).build();
	}
	
}
