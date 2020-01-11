/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.auth;

import static io.leitstand.security.auth.UserName.userName;
import static io.leitstand.security.login.log.service.UserLoginState.FAILED;
import static io.leitstand.security.login.log.service.UserLoginState.PASSED;
import static java.lang.String.format;
import static javax.json.Json.createReader;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.INVALID;

import java.io.IOException;
import java.util.logging.Logger;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.security.enterprise.credential.Password;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.leitstand.security.auth.UserName;
import io.leitstand.security.auth.user.LoginManager;
import io.leitstand.security.login.log.service.UserLoginAuditLogService;

@Dependent
public class DefaultLoginManager implements LoginManager{

	private static final String USER_AGENT_HTTP_HEADER = "User-Agent";
	private static final Logger LOG  = Logger.getLogger(DefaultLoginManager.class.getName());

	@Inject
	private IdentityStore is;
	
	@Inject
	private UserLoginAuditLogService audit;
	
	/**
	 * Reads the JSON body of a login request to create a <code>UsernamePasswordCredential</code> instance.
	 * @param reader the JSON reader of the login request body
	 * @return the created <code>UsernamePasswordCredential</code>.
	 */
	static UsernamePasswordCredential readCredentials(JsonReader reader) {
		JsonObject request 	= reader.readObject();
		String	   userName  	= request.getString("user_name");
		Password   password = new Password(request.getString("password"));
		return new UsernamePasswordCredential(userName, password);
	}
	
	/**
	 * Processes a login request and logs the login attempt outcome.
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @return <code>INVALID_RESULT</code> if the provided credentials were invalid, 
	 * otherwise information about the authenticated user and its assigned roles
	 */
	@Override
	public CredentialValidationResult login(HttpServletRequest request, 
										 	HttpServletResponse response) {
		
		try(JsonReader reader = createReader(request.getReader())){
			
			// Read and verify credential data
			UsernamePasswordCredential credential = readCredentials(reader);
			CredentialValidationResult result = is.validate(credential);
			
			UserName userName = userName(credential.getCaller());
			// Send unauthenticated reply if credentials are invalid
			if(result.getStatus() == INVALID) {
				audit.log(request.getRemoteAddr(),
						  request.getHeader(USER_AGENT_HTTP_HEADER),
						  userName, 
						  FAILED);	
				return result;
			}
			
			audit.log(request.getRemoteAddr(), 
					  request.getHeader(USER_AGENT_HTTP_HEADER), 
					  userName, 
					  PASSED);
			
			return result;

		} catch(JsonException | IOException  e) {
			LOG.fine(() -> format("Cannot parse credentials: %s",e.getMessage()));
			return INVALID_RESULT;
		}
	}
	
}
