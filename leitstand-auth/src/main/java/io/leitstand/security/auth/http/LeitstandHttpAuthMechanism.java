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
package io.leitstand.security.auth.http;

import static io.leitstand.security.auth.UserName.userName;
import static java.lang.String.format;
import static java.util.logging.Logger.getLogger;
import static javax.security.enterprise.AuthenticationStatus.NOT_DONE;
import static javax.security.enterprise.AuthenticationStatus.SEND_FAILURE;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.INVALID;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.NOT_VALIDATED;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

import java.util.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.leitstand.security.auth.user.LoginManager;


/**
 * The default RBMS HTTP authentication mechanism.
 * <p>
 * For login requests, i.e. requests to <code>/api/v1/_login</code>, the user credentials
 * are read from the request body and passed to the identity store for verification. 
 * The credentials are provided as JSON object, where <code>user_id</code> contains the user ID and 
 * <code>password</code> contains the password.
 * <code><pre>
 * {"user_id":"martin",
 *  "password":"top-secret"}
 * </pre></code>
 * Provided that the credentials are valid, an {@link AccessToken} is created and sent 
 * as <code>rtb-access</code> cookie to the client. 
 * All login attempts are logged in the login audit log.
 * </p>
 * For all other requests, the first step is to check whether a HTTP <i>Authorization</i> header is present.
 * If so, the header is decoded an the credentials are verified.
 * <p>
 * If no HTTP <i>Authorization</i> header is present, the request is scanned for the <code>rtb-access</code> cookie.
 * If a cookie is present, the access token is verified. 
 * </p>
 * If no access information is available, the request is unauthenticated and request processing is rejected.
 */
@ApplicationScoped
public class LeitstandHttpAuthMechanism implements HttpAuthenticationMechanism{
	
	private static final Logger LOG = getLogger(LeitstandHttpAuthMechanism.class.getName());
	
	/**
	 * Returns <code>true</code> if the request is a login request, 
	 * i.e. a <code>POST</code> request submitted to <code>/api/v1/_login</code>.
	 * @param request the HTTP request.
	 * @return <code>true</code> if the request is a login request
	 */
	static boolean isLoginRequest(HttpServletRequest request) {
		return request.getRequestURI().startsWith("/api/v1/login");
	}

	/**
	 * Returns <code>true</code> if the request is an API request, either invoking the REST API or fetching UI metadata, which is also an API.
	 * @param request the HTTP request.
	 * @return <code>true</code> if the requests is a login request.
	 */
	static boolean isApiRequest(HttpServletRequest request) {
		return request.getRequestURI().startsWith("/api/v1");
	}
	
	@Inject
	private Instance<AccessTokenManager> accessTokenManagers;
	
	@Inject
	private LoginManager loginManager;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public AuthenticationStatus validateRequest(HttpServletRequest request, 
												HttpServletResponse response,
												HttpMessageContext context) throws AuthenticationException {	
		
		if(isApiRequest(request)) {
			if(isLoginRequest(request)) {
				if(request.getRequestURI().startsWith("/api/v1/login/_login") && "POST".equals(request.getMethod())) {
					return login(request,
								 response,
								 context);
				}
				// Grant unauthenticated access to login configurationa and SSO flows.
				return NOT_DONE;
			}
			
			return authenticate(request,
								response,
								context);
			
		}
		// Do not authenticate access to static resources
		return NOT_DONE;
	}

	/**
	 * Processes a login request and logs the login attempt outcome.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @param context the context to be notified about a successful login attempt
	 * @return {@link AuthenticationStatus#SUCCESS} if the identity store accepted the credentials 
	 * and {@link AuthenticationStatus#SEND_FAILURE} in any other case.
	 */
	protected AuthenticationStatus login(HttpServletRequest request, 
										 HttpServletResponse response, 
										 HttpMessageContext context ) {
		
		CredentialValidationResult result = loginManager.login(request, response);
		if(isUnauthenticated(result)) {
			return unauthenticated(response);
		}
		
		// Issue access token to authenticate further requests
		for(AccessTokenManager manager : accessTokenManagers) {
			if(manager.issueAccessToken(request, 
										response, 
										userName(result.getCallerPrincipal()),
										result.getCallerGroups())) {
				break;
			}
		}
		
		return context.notifyContainerAboutLogin(result);
		
	}
	
	/**
	 * Attempts to authenticate a non-login request.
	 * <p>
	 * First the HTTP <i>Authorization</i> header is verified, if such a header is present.
	 * Second the HTTP request is scanned for the <code>rtb-access</code> cookie.
	 * If a cookie is present, the cookie is verified.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @param context the context to be notified about successfully authenticated requests
	 * @return {@link AuthenticationStatus#NOT_DONE} if no credential data was found, 
	 *         {@link AuthenticationStatus#SEND_FAILURE} if the credentials are invalid and 
	 *         {@link AuthenticationStatus#SUCCESS} if the identity store accepted the provided credentials.
	 */
	protected AuthenticationStatus authenticate(HttpServletRequest request,
			  									HttpServletResponse response,
			  									HttpMessageContext context) {
		
		
		for(AccessTokenManager manager : accessTokenManagers) {
			CredentialValidationResult result = manager.validateAccessToken(request, response);
			LOG.fine(() -> format("%s %s: %s", 
								  request.getRequestURI(), 
								  manager.getClass().getSimpleName(), 
								  result));
			if(result.getStatus() == NOT_VALIDATED) {
				continue; // Try next manager, if no statement was made.
			}
			if(result.getStatus() == INVALID) {
				return unauthenticated(response);
			}
			return context.notifyContainerAboutLogin(result);
		}
		return unauthenticated(response);

	}
		

	private boolean isUnauthenticated(CredentialValidationResult result) {
		return result.getStatus() == INVALID;
	}

	@Override
	public void cleanSubject(HttpServletRequest request, 
							 HttpServletResponse response,
				 			 HttpMessageContext httpMessageContext) {
		for(AccessTokenManager manager : accessTokenManagers) {
			LOG.fine(() -> format("%s Called %s to invalidate access token", 
					  			  request.getRequestURI(), 
					  			  manager.getClass().getSimpleName()));			
			manager.invalidateAccessToken(request, response);
		}
		httpMessageContext.cleanClientSubject();
	}
	
	/**
	 * Creates a failed authentication attempt reply.
	 * @param response the HTTP response
	 * @return {@link AuthenticationStatus#SEND_FAILURE} to inform about the failed request authentication
	 */
	protected AuthenticationStatus unauthenticated(HttpServletResponse response) {
		response.setStatus(SC_UNAUTHORIZED);
		response.setHeader("Cache-Control", "no-cache");
		response.setHeader("Pragma","no-cache");
		return SEND_FAILURE;
	}

	
}
