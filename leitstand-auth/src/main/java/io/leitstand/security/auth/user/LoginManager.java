/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.user;

import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The <code>LoginManager</code> validates the credentials of a login requests and 
 * logs the outcome of the validation in the login audit log.
 *
 * @see UserLoginAuditLogService
 */
public interface LoginManager {
	
	/**
	 * Processes a login request and logs the login attempt outcome.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @return <code>INVALID_RESULT</code> if the provided credentials were invalid, 
	 * otherwise information about the authenticated user and its assigned roles
	 */
	CredentialValidationResult login(HttpServletRequest request, 
									 HttpServletResponse response);
		

}
